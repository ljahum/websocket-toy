package main

import (
	"bufio"
	"client/myaes"
	"client/sign"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"math/big"
	"os"
	"strconv"
)

var PubKey *rsa.PublicKey
var PriKey *rsa.PrivateKey

var shearedkey []byte

var userName string

type msg_to_server struct {
	ID      string `json:"ID"`
	Payload string `json:"Payload"`
	Sign    string `json:"Sign"`
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

		fmt.Println("done")
	} else {
		fmt.Println("秘钥交换出错")
		return false
	}
	//发送公钥
	key, _ := os.ReadFile("./rsa_private.key")
	pkcs8keyStr, _ := pem.Decode(key)
	//解析成pkcs8格式私钥
	//privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	rowKey, _ := x509.ParsePKCS8PrivateKey(pkcs8keyStr.Bytes)
	PriKey = rowKey.(*rsa.PrivateKey)
	PubKey = &PriKey.PublicKey
	JsonPubKey, _ := json.Marshal(PubKey)
	conn.WriteMessage(websocket.TextMessage, JsonPubKey)
	//测试签名
	msg := "verifiable message"
	encBytes := myaes.EncryptecbMode_withPadding([]byte(msg), shearedkey)
	S := sign.RsaSign(PriKey, []byte(msg))

	//反正b64一下
	b64encbytes := base64.StdEncoding.EncodeToString(encBytes)
	b64signature := base64.StdEncoding.EncodeToString(S)
	data := msg_to_server{userName, b64encbytes, b64signature}

	json_data, _ := json.Marshal(data)
	conn.WriteMessage(websocket.TextMessage, json_data)

	return true
}
func main() {

	//var username string

	// 主机名
	var host string
	// 端口号
	var port int

	// StringVar用指定的名称、控制台参数项目、默认值、使用信息注册一个string类型flag，并将flag的值保存到p指向的变量
	flag.StringVar(&userName, "u", "", "用户名,必填")
	//flag.StringVar(&password, "p", "", "密码,默认为空")
	flag.StringVar(&host, "h", "127.0.0.1", "主机名,默认 127.0.0.1")
	flag.IntVar(&port, "P", 9999, "端口号,默认为9999")

	// 从arguments中解析注册的flag。必须在所有flag都注册好而未访问其值时执行。未注册却使用flag -help时，会返回ErrHelp。
	flag.Parse()
	//userName = "user1"
	// 打印
	fmt.Printf("username=%v host=%v port=%v\n", userName, host, port)
	if userName == "" {
		fmt.Println("用户名必填捏")
	}
	dl := websocket.Dialer{}
	url := "ws://" + host + ":" + strconv.Itoa(port)
	conn, _, err := dl.Dial(url, nil)

	if initkey(conn) == false {
		fmt.Println("秘钥协商失败")
	} else {
		fmt.Println("秘钥协商成功")
	}

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
		//加密 编码 (base64真的重要吗?)
		encBytes := myaes.EncryptecbMode_withPadding([]byte(msg), shearedkey)
		S := sign.RsaSign(PriKey, []byte(msg))

		//反正b64一下
		b64encbytes := base64.StdEncoding.EncodeToString(encBytes)
		b64signature := base64.StdEncoding.EncodeToString(S)
		data := msg_to_server{userName, b64encbytes, b64signature}

		json_data, _ := json.Marshal(data)
		conn.WriteMessage(websocket.TextMessage, json_data)

	}
}

func myPow(M *big.Int, E *big.Int, N *big.Int) *big.Int {
	var c big.Int
	c.Exp(M, E, N)

	return &c
}
