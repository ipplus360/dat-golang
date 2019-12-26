package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func ReadAll(filePth string) ([]byte, error) {
	f, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

func BytesToInt(b []byte) uint32 {
	bytesBuffer := bytes.NewBuffer(b)
	var tmp int32
	binary.Read(bytesBuffer, binary.LittleEndian, &tmp)
	return uint32(tmp)
}

func inet_aton(ipnr string) uint32 {
	bits := strings.Split(ipnr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])
	var sum uint32
	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)
	return sum
}

var data, _ = ReadAll("D:\\dddd.dat")
var offset_addr = BytesToInt(data[:8])
var offset_owner = BytesToInt(data[8:16])
var offset_info = data[16:]
var reg, err = regexp.Compile("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$")

const base_len uint32 = 64

func locate(ip string) []string {
	if !reg.Match([]byte(ip)) {
		return []string{"Error IP"}
	}
	nip := inet_aton(ip)
	var record_min uint32 = 0
	record_max := offset_addr/base_len - 1
	record_mid := (record_min + record_max) / 2
	for record_max-record_min >= 0 {
		mult_re_ba := record_mid * base_len
		minip := BytesToInt(offset_info[mult_re_ba : mult_re_ba+4])
		maxip := BytesToInt(offset_info[mult_re_ba+4 : mult_re_ba+8])
		switch {
		case nip < minip:
			record_max = record_mid - 1
		case (nip == minip) || (nip > minip && nip < maxip) || (nip == maxip):
			addr_begin := BytesToInt(offset_info[mult_re_ba+8 : mult_re_ba+16])
			addr_length := BytesToInt(offset_info[mult_re_ba+16 : mult_re_ba+24])
			owner_begin := BytesToInt(offset_info[mult_re_ba+24 : mult_re_ba+32])
			owner_length := BytesToInt(offset_info[mult_re_ba+32 : mult_re_ba+40])
			//bd_lon := string(offset_info[mult_re_ba+40 : mult_re_ba+52])
			//bd_lat := string(offset_info[mult_re_ba+52 : mult_re_ba+64])
			wgs_lon := string(offset_info[mult_re_ba+40 : mult_re_ba+52])
			wgs_lat := string(offset_info[mult_re_ba+52 : mult_re_ba+64])
			//radius := string(offset_info[mult_re_ba+88 : mult_re_ba+100])
			//scene := string(offset_info[mult_re_ba+100 : mult_re_ba+112])
			//accuracy := string(offset_info[mult_re_ba+112 : mult_re_ba+124])
			addr_bundle := string(offset_info[addr_begin : addr_begin+addr_length])
			addr := strings.Split(addr_bundle, "|")
			owner := offset_info[owner_begin : owner_begin+owner_length]

			tmp_list := []string{strconv.Itoa(int(minip)), strconv.Itoa(int(maxip)), addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], string(wgs_lon), string(wgs_lat),  string(owner)}
			var res_list = make([]string, len(tmp_list))
			for i, item := range tmp_list {
				item = strings.Replace(item, "\x00", "", -1)
				res_list[i] = item
			}
			return res_list
		case nip > maxip:
			record_min = record_mid + 1
		default:
			fmt.Print("Error Case")
		}
		record_mid = (record_min + record_max) / 2
	}
	return []string{"Not Found"}
}

func main() {
	var ip string
	for true {
		fmt.Print("输入IP：")
		fmt.Scanln(&ip)
		fmt.Println(strings.Join(locate(ip), "|"))
	}
}
