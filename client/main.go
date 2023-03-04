package main

import (
	"bufio"
	"client/myaes"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"os"

	"github.com/gorilla/websocket"
)

var shearedkey []byte

const userName = "user1"

type msg_to_server struct {
	ID      string `json:"ID"`
	Payload string `json:"Payload"`
}

type DHExchange struct {
	P        *big.Int
	G        *big.Int
	A        *big.Int
	B        *big.Int
	Username string
}

func initkey(conn *websocket.Conn) bool {

	var server_hello DHExchange
	//recv server hello
	_, plaintext, _ := conn.ReadMessage()
	_ = json.Unmarshal(plaintext, &server_hello)

	//send client hello
	P := server_hello.P
	G := server_hello.G
	bigA := server_hello.A
	b, _ := rand.Prime(rand.Reader, 10)
	bigB := myPow(G, b, P)
	server_hello.B = bigB
	server_hello.Username = userName
	client_hello := server_hello

	plaintext, _ = json.Marshal(&client_hello)
	conn.WriteMessage(websocket.TextMessage, plaintext)

	//compelet key
	k2 := myPow(bigA, b, P)
	tmphash := md5.New()
	tmphash.Write(k2.Bytes())
	shearedkey = tmphash.Sum(nil)

	//test key
	_, plaintext, _ = conn.ReadMessage()
	checkEnc := myaes.DecryptecbMode_withUnpadding(plaintext, shearedkey)
	fmt.Println("decrypto test:", string(checkEnc))
	if string(checkEnc) == "hello" {
		return true
		fmt.Println("done")
	} else {
		return false
	}

	return true
}
func main() {

	dl := websocket.Dialer{}
	conn, _, err := dl.Dial("ws://127.0.0.1:9999", nil)
	if initkey(conn) == false {
		fmt.Println("秘钥协商失败")
	} else {
		fmt.Println("秘钥协商成功")
	}
	shearedkey = []byte("1111111111111111")
	//os.Exit(0)
	if err != nil {
		return
	}
	//conn.WriteMessage(websocket.TextMessage, []byte("hello"))
	go send(conn) //go 语句开启一个新的运行期线程
	//但不能收发都用 go否则主进程会掉
	//Go 语言支持并发，我们只需要通过 go 关键字来开启 goroutine 即可。
	//
	//goroutine 是轻量级线程，goroutine 的调度是由 Golang 运行时进行管理的。
	for {
		_, data, err := conn.ReadMessage()
		plaintext := myaes.DecryptecbMode_withUnpadding(data, shearedkey)
		if err != nil {
			break
		}
		//myaes.DecryptAES(a)
		fmt.Println("接收", string(plaintext))
	}
}

func send(conn *websocket.Conn) {
	for {

		reader := bufio.NewReader(os.Stdin)

		rl, _, _ := reader.ReadLine()
		msg := userName + ":" + string(rl)
		//fmt.Println(msg)
		encBytes := myaes.EncryptecbMode_withPadding([]byte(msg), shearedkey)
		b64encbytes := base64.StdEncoding.EncodeToString(encBytes)
		//pack
		//fmt.Println(b64encbytes)
		data := msg_to_server{userName, b64encbytes}

		json_data, _ := json.Marshal(data)
		conn.WriteMessage(websocket.TextMessage, json_data)

	}
}

func myPow(M *big.Int, E *big.Int, N *big.Int) *big.Int {
	var c big.Int
	c.Exp(M, E, N)

	return &c
}
