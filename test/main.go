package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"math/big"
	"test/myaes"
)

func main() {
	text := []byte("1111222233334444")
	for i := 0; i < len(text)/16; i++ {
		fmt.Println(i)
	}
	//fmt.Println(string(text[0:16]))
	//fmt.Println(string(text[16:32]))
	key := []byte("1111222233334444")
	enc := myaes.EncryptecbMode_withPadding(text, key)
	fmt.Println(enc)
	fmt.Println(len(enc))
	dec := myaes.DecryptecbMode_withUnpadding(enc, []byte("1111222233334445"))
	fmt.Println(string(dec))
	fmt.Println(dec)
	fmt.Println(len(dec))

}

func myPow(M *big.Int, E *big.Int, N *big.Int) *big.Int {
	var c big.Int
	c.Exp(M, E, N)

	return &c
}
func InitDB() {
	db, err := sql.Open("mysql", "root:123321@tcp(192.168.0.103:3306)/database?charset=utf8")
	if err != nil { // 连接失败
		fmt.Printf("connect mysql fail ! [%s]", err)
	} else { // 连接成功
		fmt.Println("connect to mysql success")
	}
	sqlStr := "SELECT * FROM `user_tab` WHERE `index`=1"
	rows, err := db.Query(sqlStr)
	if err != nil {
		panic("fail to connect databse,err:")
	}
	defer rows.Close()
	for rows.Next() {
		var u User
		err := rows.Scan(&u.index, &u.Name, &u.Passwd)
		if err != nil {
			fmt.Printf("scan failed, err:%v\n", err)
		}
		fmt.Printf("name:%s passwd:%s \n", u.Name, u.Passwd)
	}

	//DB = db
	//return db
}

//	func GetDB() *sql.DB {
//		return DB
//	}
type User struct {
	index  int64
	Name   string
	Passwd string
}

//var DB *sql.DB

type DHExchange struct {
	P *big.Int
	G *big.Int
	A *big.Int
	B *big.Int
}
