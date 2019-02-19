package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/hasnainvirk/test/dataGeneratorLib"

	"github.com/hasnainvirk/test/mycryptolib"

	ttnsdk "github.com/TheThingsNetwork/go-app-sdk"
	ttnlog "github.com/TheThingsNetwork/go-utils/log"
	"github.com/TheThingsNetwork/go-utils/log/apex"
	"github.com/TheThingsNetwork/ttn/core/types"
)

// dataBuffer is the buffer that contains generated data for the Fragmentation test
var dataBuffer []byte

// genAppKey is used to generate mcRootKey for a device
var genAppKey = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x1F}

// this key will be used to deruve session keys for multicast. This key's encrypted form will be transported to the device over air
var mcKey = []byte{0x1F, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}

// Root key is used to derive Key encreyption key (mcKeKey)
var mcRootKey []byte

// Key encryption key is a device lifetime key, will be used to decrypt and retrieve
// mcKey which will in turn be used to derive appSkey and NwkSkey for multicast session
var mcKeKey []byte

// This is the encrypted form of mcKey defined above
var mcKeyEncrypted []byte

// application and network session keys will be derived using mcKey
var mcNwkSkey []byte
var mcAppSkey []byte

var mcastAddress uint32 = 0xDEADBEEF
var mcastDlFreq uint32 = 869400000 / 100
var mcastDR uint8 = 3

type clkSyncCMD int
type mcastCtrlCMD int
type fragCtrlCMD int

// Command identifiers for ClockSync Package
const (
	ClockSyncVersion clkSyncCMD = iota
	ClockSyncAppTime
	ClockSyncTimePeriodicity
	ClockSyncForceResync
)

// Command identifiers for Multicast control package
const (
	MulticastVersion mcastCtrlCMD = iota
	MulticastGroupStatus
	MulticastGroupSetup
	MulticastGroupDelete
	MulticastClassCSession
	MulticastClassBSession
)

// Command identifiers for Fragmentation control package
const (
	FragVersion fragCtrlCMD = iota
	FragGroupStatus
	FragGroupSetup
	FragGroupDelete
	DataFragment = 0x08
)

// UnixGPSEpochDiff is the difference between Unix time and GPS epoch time
const UnixGPSEpochDiff = 315964800

// CurrentTAIMinusUTC is the current difference in Unix epoch time (as of 2018) between TAI time and UTC
const CurrentTAIMinusUTC = 37

// GPSEpochTAIMinusUTC is the current difference in GPS epoch time (as of 2018) between TAI time and UTC
const GPSEpochTAIMinusUTC = 19

// ClockSyncPort is the default port for ClockSyncControl Plugin
const ClockSyncPort = 202

// MulticastPort is the default port for MulticastControl Plugin
const MulticastPort = 200

// FragPort is the default port for FragmentationControl Plugin
const FragPort = 201

const (
	sdkClientName = "my-amazing-app"
)

type waitTask struct {
	closed chan struct{}
	wg     sync.WaitGroup
	ticker *time.Ticker
}

// This method runs forever, until ctrl-c pressed
func (t *waitTask) Run() {
	for {
		select {
		case <-t.closed:
			return
		case <-t.ticker.C:
			// do nothing
		}
	}
}

func (t *waitTask) Stop() {
	close(t.closed)
	t.wg.Wait()
}

func getCurrentGPSTime() uint32 {
	now := time.Now()
	fmt.Println("Current Time: ", now.String())
	secs := uint32(now.Unix()) - UnixGPSEpochDiff
	secs += (CurrentTAIMinusUTC - GPSEpochTAIMinusUTC)

	return uint32(secs)
}

func main() {

	// Generate 1K + 2 of data for Frag test
	result, _ := dataGeneratorLib.Generate(`foo[a-z]{1002}bar`)
	dataBuffer = make([]byte, 1002)
	copy(dataBuffer, result[0:1002])
	// Make the padding bytes zero
	dataBuffer[1002-1] = 0
	dataBuffer[1002-2] = 0
	fmt.Println("Encoded Data: ", dataBuffer)
	fmt.Println("Data size: ", len(dataBuffer))

	// Empty buffer as input, as we need 0x00 | pad16
	input := make([]byte, 16)
	mcRootKey = make([]byte, 16)
	mcKeKey = make([]byte, 16)
	mcNwkSkey = make([]byte, 16)
	mcAppSkey = make([]byte, 16)
	mcKeyEncrypted = make([]byte, 16)
	testMcKeyRetrieval := make([]byte, 16)

	//derive mcKeKey via mcRootKEy using genAppKey
	mycryptolib.Crypt(mycryptolib.AESEncrypt, genAppKey, input, mcRootKey)
	mycryptolib.Crypt(mycryptolib.AESEncrypt, mcRootKey, input, mcKeKey)

	// store encrypted mcKey in the mcKeyEncrypted
	mycryptolib.Crypt(mycryptolib.AESEncrypt, mcKeKey, mcKey, mcKeyEncrypted)
	mycryptolib.Crypt(mycryptolib.AESDecrypt, mcKeKey, mcKeyEncrypted, testMcKeyRetrieval)

	// derive Multicast App session key
	input[0] = 0x01
	binary.LittleEndian.PutUint32(input[1:], mcastAddress)
	mycryptolib.Crypt(mycryptolib.AESEncrypt, mcKey, input, mcAppSkey)
	// derive Multicast Network session key
	input[0] = 0x02
	mycryptolib.Crypt(mycryptolib.AESEncrypt, mcKey, input, mcNwkSkey)

	fmt.Printf("mcRootKey Derived: %s\n", hex.EncodeToString(mcRootKey))
	fmt.Printf("mcKeKey Derived: %s\n", hex.EncodeToString(mcKeKey))
	fmt.Printf("mcKey: %s\n", hex.EncodeToString(mcKey))
	fmt.Printf("mcAppSkey Derived: %s\n", hex.EncodeToString(mcAppSkey))
	fmt.Printf("mcNwkSkey Derived: %s\n", hex.EncodeToString(mcNwkSkey))
	fmt.Printf("Encrypted mcKey %s\n", hex.EncodeToString(mcKeyEncrypted))
	fmt.Printf("Decryped mcKey (Test) %s\n", hex.EncodeToString(testMcKeyRetrieval))

	log := apex.Stdout() // We use a cli logger at Stdout
	log.MustParseLevel("debug")
	ttnlog.Set(log) // Set the logger as default for TTN

	// We get the application ID and application access key from the environment
	appID := os.Getenv("TTN_APP_ID")
	appAccessKey := os.Getenv("TTN_APP_ACCESS_KEY")

	// Create a new SDK configuration for the public community network
	config := ttnsdk.NewCommunityConfig(sdkClientName)
	config.ClientVersion = "2.0.5" // The version of the application

	// Create a new SDK client for the application
	client := config.NewClient(appID, appAccessKey)

	// Make sure the client is closed before the function returns
	// In your application, you should call this before the application shuts down
	defer client.Close()

	// Manage devices for the application.
	devices, err := client.ManageDevices()
	if err != nil {
		log.WithError(err).Fatal("my-amazing-app: could not get device manager")
	}

	// List the first 10 devices
	deviceList, err := devices.List(10, 0)
	if err != nil {
		log.WithError(err).Fatal("my-amazing-app: could not get devices")
	}
	log.Info("my-amazing-app: found devices")
	for _, device := range deviceList {
		fmt.Printf("- %s", device.DevID)
	}

	// initialize MQTT pub/sub
	pubsub, err := client.PubSub()
	if err != nil {
		log.WithError(err).Fatalf("%s: could not get application pub/sub", sdkClientName)
	}

	allDevicesPubSub := pubsub.AllDevices()

	// goroutine to handle all activations
	activations, err := allDevicesPubSub.SubscribeActivations()
	if err != nil {
		log.WithError(err).Fatalf("%s: could not subscribe to activations", sdkClientName)
	}

	go func() {
		for activation := range activations {
			log.WithFields(ttnlog.Fields{
				"appEUI":  activation.AppEUI.String(),
				"devEUI":  activation.DevEUI.String(),
				"devAddr": activation.DevAddr.String(),
			}).Info("my-amazing-app: received activation")
		}
	}()

	// subscribe to my device
	myDevice := pubsub.Device("hasnain-k64f-555")

	// handle any uplink message
	uplink, err := myDevice.SubscribeUplink()
	if err != nil {
		log.WithError(err).Fatalf("%s: could not subscribe to Uplink messages", sdkClientName)
	}

	go func() {
		for message := range uplink {

			hexpayload := hex.EncodeToString(message.PayloadRaw)
			var msg types.DownlinkMessage
			if message.PayloadRaw != nil && message.FPort == MulticastPort {
				// handle multicas control packetc here
				log.WithField("MCAST:", hexpayload).Infof("%s: received uplink", sdkClientName)
				for i := 0; i < len(message.PayloadRaw); i++ {
					switch message.PayloadRaw[i] {
					case byte(MulticastVersion):
						fmt.Printf("Multicast Pacakge Identifier: %d, Package Version: %d \n", message.PayloadRaw[i+1],
							message.PayloadRaw[i+2])
						i += 2
					case byte(MulticastGroupStatus):
						i++
						if message.PayloadRaw[i] == 0 {
							fmt.Println("No Multicast group defined in the device yet")
						} else {
							// get NbTotalGroups field (3bits in the upper half of the byte)
							listCount := int((message.PayloadRaw[i] & 0xF0) >> 4)
							fmt.Printf("NbTotalGroups: %d\n", listCount)
							for j := 0; j < listCount; j++ {
								i++
								fmt.Printf("Multicast Group: %x, Address: %x \n", message.PayloadRaw[i+j],
									message.PayloadRaw[i+j+1:i+j+5])
								i += 4
							}
						}
					case byte(MulticastGroupSetup):
						i++
						payload := message.PayloadRaw[i]
						gID := payload & 0x03
						// check the third bit (IDError) if its on
						if (payload & (1 << 2)) != 0 {
							fmt.Printf("The Multicast Group '%d' (to be setup)is not defined at the device\n", gID)
						} else {
							fmt.Printf("Multicast Group '%d' has successfully been setup\n", gID)
						}
					case byte(MulticastGroupDelete):
						i++
						payload := message.PayloadRaw[i]
						gID := payload & 0x03
						// check the third bit (MCGroupUndefined)
						if (payload & (1 << 2)) != 0 {
							fmt.Printf("The Multicast Group '%d' (to be deleted) is not defined at the device\n", gID)
						} else {
							fmt.Printf("Multicast Group '%d' has successfully been deleted\n", gID)
						}
					case byte(MulticastClassCSession):
						i++
						statusField := message.PayloadRaw[i]
						timeTostart := message.PayloadRaw[i+1 : i+1+4]
						i += 3

						if statusField&(1<<2) >= 1 {
							fmt.Println("Group Setup: Datartae not supported by device")
						} else if statusField&(1<<3) >= 1 {
							fmt.Println("Group Setup: Frequency not supported by device")
						} else if statusField&(1<<4) >= 1 {
							fmt.Println("Group Setup: McGroup is not defined ")
						} else {
							fmt.Println("Multicast Group Setup Respons 'OK'")
							fmt.Printf("Gid: %x, Time to start (seconds) %d\n", (statusField & 0x03), binary.LittleEndian.Uint32(timeTostart))
						}

					}
				}
			} else if message.PayloadRaw != nil && message.FPort == ClockSyncPort {
				log.WithField("CLKSYNC:", hexpayload).Infof("%s: received uplink", sdkClientName)

				for i := 0; i < len(message.PayloadRaw); i++ {
					switch message.PayloadRaw[i] {
					case byte(ClockSyncAppTime):
						msg.FPort = ClockSyncPort
						fmt.Println("Clock Sync Request received .. ")
						time := getCurrentGPSTime()

						fmt.Println("Current GPS time 32bit", time)
						var devTime uint32
						var timeDelta uint32
						i++
						timeSlice := message.PayloadRaw[i : i+4]
						i += 4
						token := message.PayloadRaw[i]
						i++

						fmt.Println("TimeSlice ", hex.EncodeToString(timeSlice), " Token ", token)
						devTime = binary.LittleEndian.Uint32(timeSlice)

						timeDelta = time - devTime

						b := make([]byte, 6)
						b[0] = byte(ClockSyncAppTime)
						binary.LittleEndian.PutUint32(b[1:], timeDelta)
						b[5] = byte(token & 0x0F)
						msg.PayloadRaw = b
						out := hex.EncodeToString(msg.PayloadRaw)
						log.WithField("CLKSYNC:", out).Infof("%s: sending downlink", sdkClientName)
						err := myDevice.Publish(&msg)

						if err != nil {
							log.WithError(err).Fatalf("%s: couldn't send a downlink", sdkClientName)
						}

					case byte(ClockSyncTimePeriodicity):
						i++
						if message.PayloadRaw[i] == 0x01 {
							fmt.Println("Device does not support Periodic Device Time Req")
						} else {
							fmt.Println("Device ClockSyncAppTimeReq Periodicity: ", binary.LittleEndian.Uint32(message.PayloadRaw[i:i+4]))
						}
						i += 4

					case byte(ClockSyncVersion):
						i++
						fmt.Println("Package version: ", message.PayloadRaw[i:i+2])
						i++
					}
				}

			} else if message.PayloadRaw != nil && message.FPort == FragPort {
				log.WithField("FRAG:", hexpayload).Infof("%s: received uplink", sdkClientName)

				for i := 0; i < len(message.PayloadRaw); i++ {
					switch message.PayloadRaw[i] {
					case byte(FragVersion):
						i++
						fmt.Println("Package Version & Identifier", message.PayloadRaw[i:i+2])
						i++

					case byte(FragGroupDelete):
						i++
						payload := message.PayloadRaw[i]
						fragID := payload & 0x03
						// check the third bit (MCGroupUndefined)
						if (payload & (1 << 2)) != 0 {
							fmt.Printf("The Multicast Group '%d' (to be deleted) is not defined at the device\n", fragID)
						} else {
							fmt.Printf("Multicast Group '%d' has successfully been deleted\n", fragID)
						}

					case byte(FragGroupSetup):
						i++
						payload := message.PayloadRaw[i]
						var success = true
						if payload&(1<<0) != 0 {
							success = false
							fmt.Printf("FragSetup - Encoding Unsupported\n")
						}

						if (payload & (1 << 1)) != 0 {
							success = false
							fmt.Printf("FragSetup - Not enough memory\n")
						}

						if (payload & (1 << 2)) != 0 {
							success = false
							fmt.Printf("FragSetup - Session Index not supported\n")
						}

						if (payload & (1 << 3)) != 0 {
							success = false
							fmt.Printf("FragSetup - Wrong Discriptor\n")
						}

						fragIndex := (payload >> 6) & 0xC0
						fmt.Printf("FragSetup - FragIndex %d \n", fragIndex)

						// If the Frag setup command is successful, we can queue up 1K of data
						// At the moment we will use Unicast session, and we will rely on
						// Downlink pending bit <-> Automatic uplink feature of our stack
						if success {
							// Total data to sent 1002 bytes with 2 bytes of padding
							// First two fragments will be sent from here, next 165 will be sent through
							// DataFragment case
							fragmentSize := 6
							b := make([]byte, 9)
							b[0] = byte(DataFragment)
							var schedule = "replace"
							var indexAndN uint16

							for i := 0; i < len(dataBuffer); i += fragmentSize {
								indexAndN++
								binary.LittleEndian.PutUint16(b[1:], indexAndN)
								copy(b[3:], dataBuffer[i:i+6])
								msg.PayloadRaw = b
								msg.FPort = FragPort
								msg.Schedule = types.ScheduleType(schedule)
								out := hex.EncodeToString(msg.PayloadRaw)
								log.WithField("DataFragment:", out).Infof("%s: sending downlink, N %d", sdkClientName, indexAndN)
								err := myDevice.Publish(&msg)
								if err != nil {
									log.WithError(err).Fatalf("%s: couldn't send a downlink", sdkClientName)
								}

								schedule = "last"
							}

						}
					}
				}
			} else if message.PayloadRaw != nil {
				log.WithField("data:", hexpayload).Infof("%s: received uplink", sdkClientName)
				MagicSeqClkSync := hex.EncodeToString([]byte{0x01, 0x01, 0x01, 0x01})
				MagicSeqMcast := hex.EncodeToString([]byte{0x02, 0x02, 0x02, 0x02})
				MagicFragSeq := hex.EncodeToString([]byte{0x03, 0x03, 0x03, 0x03})
				if strings.Compare(hexpayload, MagicSeqClkSync) == 0 {
					// send all the requests the App server can send at once
					b := make([]byte, 5)
					/* PackageVersionReq */
					b[0] = byte(ClockSyncVersion)
					/* DeviceClockSyncAppTimePeriodicityReq */
					b[1] = byte(ClockSyncTimePeriodicity)
					b[2] = 0x0F
					/* ForceDeviceResyncReq */
					b[3] = byte(ClockSyncForceResync)
					b[4] = 0x01
					msg.PayloadRaw = b
					msg.FPort = ClockSyncPort
					out := hex.EncodeToString(msg.PayloadRaw)
					log.WithField("CLKSYNC:", out).Infof("%s: sending downlink", sdkClientName)
					err := myDevice.Publish(&msg)
					if err != nil {
						log.WithError(err).Fatalf("%s: couldn't send a downlink", sdkClientName)
					}
				} else if strings.Compare(hexpayload, MagicSeqMcast) == 0 {
					// send all the Multicast control commands at once

					b := make([]byte, 56)

					/* Package version */
					b[0] = byte(MulticastVersion)

					/* Group setup request - 1 MCAST session Gid = 0x02 */
					b[1] = byte(MulticastGroupSetup)
					b[2] = 0x02
					binary.LittleEndian.PutUint32(b[3:], mcastAddress)
					copy(b[7:], mcKeyEncrypted)
					var fcnt uint32
					binary.LittleEndian.PutUint32(b[23:], fcnt) // minFcnt 0
					fcnt = 1000
					binary.LittleEndian.PutUint32(b[27:], fcnt) // maxFcnt 1000

					/* Group Status - ask all 4*/
					b[31] = byte(MulticastGroupStatus)
					b[32] = 0x0F

					/* Group delete request - Ask to drop 0x01 (will fail)*/
					b[33] = byte(MulticastGroupDelete)
					b[34] = 0x01

					/* Class C session request request on the session that we had setup 0x02 */
					b[35] = byte(MulticastClassCSession)
					b[36] = 0x02
					// ask the device to switch session 10 seconds from now
					binary.LittleEndian.PutUint32(b[37:], getCurrentGPSTime()+60)
					// set session timout to be 32 seconds (1 << 5)
					b[41] = 5
					// set DLFreq and DR
					var buf bytes.Buffer
					buf.WriteByte(byte(mcastDlFreq))
					buf.WriteByte(byte(mcastDlFreq >> 8))
					buf.WriteByte(byte(mcastDlFreq >> 16))
					copy(b[42:], buf.Bytes())
					b[45] = mcastDR

					/* Try to setup class B session, will fail */
					b[46] = byte(MulticastClassBSession)
					binary.LittleEndian.PutUint32(b[47:], getCurrentGPSTime()+10)
					b[51] = 5
					copy(b[52:], buf.Bytes())
					b[55] = mcastDR

					msg.PayloadRaw = b
					msg.FPort = MulticastPort
					out := hex.EncodeToString(msg.PayloadRaw)
					log.WithField("MCAST:", out).Infof("%s: sending downlink", sdkClientName)
					err := myDevice.Publish(&msg)
					if err != nil {
						log.WithError(err).Fatalf("%s: couldn't send a downlink", sdkClientName)
					}
				} else if strings.Compare(hexpayload, MagicFragSeq) == 0 {
					/* Try sending Frag session mac commands - Will do DataFragment and StatusRequest later when the
					   response is received */
					b := make([]byte, 14)

					/* Package version */
					b[0] = byte(FragVersion)

					/* Frag Session Delete Request - Will fail as no session exists at this time */
					b[1] = byte(FragGroupDelete)
					b[2] = 0x00

					/* Frag Session Setup Request - RFU = 0, FragIndex = 0, McGroupBitMask = 0x02 */
					b[3] = byte(FragGroupSetup)
					b[4] = 0x02
					// send 167 fragments with size 6, (167 * 6 = 1002) padding will be 2 bytes
					var nbFrag uint16 = 167
					var fragSize uint8 = 6
					b[5] = byte(nbFrag)
					b[6] = byte(nbFrag >> 8)
					b[7] = fragSize
					// block ack delay of 2, algo is 0 (FCC algo)
					b[8] = 0x02
					// Padding in the last frame 2 bytes
					b[9] = 0x02
					// set descriptor
					b[10] = 'A'
					b[11] = 'T'
					b[12] = 'O'
					b[13] = 'F'

					msg.PayloadRaw = b
					msg.FPort = FragPort
					out := hex.EncodeToString(msg.PayloadRaw)
					log.WithField("FRAG:", out).Infof("%s: sending downlink", sdkClientName)
					err := myDevice.Publish(&msg)
					if err != nil {
						log.WithError(err).Fatalf("%s: couldn't send a downlink", sdkClientName)
					}

				}
			}

		}
	}()

	// handle ctrl-c for graceful exit
	task := &waitTask{
		closed: make(chan struct{}),
		ticker: time.NewTicker(time.Second * 2),
	}

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	task.wg.Add(1)
	go func() { defer task.wg.Done(); task.Run() }()

	select {
	case sig := <-c:
		fmt.Printf("Got %s signal. Aborting...\n", sig)
		task.Stop()
	}

}
