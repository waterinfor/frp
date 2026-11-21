// pkg/util/net/knock.go
// frp 0.72.0 预握手校验（port knock 式前导包）
// 客户端连上 frps 后先发 24 字节：8 字节 Unix 时间戳 + 16 字节 HMAC-SHA256(key, 时间戳)
// 服务端校验失败（超时/时间偏差>30s/MAC 不对）直接静默断开，不回任何字节。
// 密钥取自环境变量 FRP_KNOCK_KEY；为空则不启用，行为与原版一致。
package net

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	libnet "github.com/fatedier/golib/net"
)

const (
	knockTSLen   = 8
	knockMACLen  = 16
	knockLen     = knockTSLen + knockMACLen
	knockSkew    = 30 * time.Second
	knockReadTO  = 5 * time.Second
	knockPending = 256 // 同时在校验中的连接上限，防慢速连接耗尽资源
)

func knockKey() []byte {
	if k := os.Getenv("FRP_KNOCK_KEY"); k != "" {
		return []byte(k)
	}
	return nil
}

func knockMAC(key, ts []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("frp-knock-v1"))
	m.Write(ts)
	return m.Sum(nil)[:knockMACLen]
}

// 客户端：拨号成功后、TLS/websocket 之前先写前导包
func DialHookKnock() libnet.AfterHookFunc {
	key := knockKey()
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if key == nil {
			return ctx, c, nil
		}
		buf := make([]byte, knockLen)
		binary.BigEndian.PutUint64(buf[:knockTSLen], uint64(time.Now().Unix()))
		copy(buf[knockTSLen:], knockMAC(key, buf[:knockTSLen]))
		if _, err := c.Write(buf); err != nil {
			return nil, nil, err
		}
		return ctx, c, nil
	}
}

// 服务端：包装 bindPort 的 listener，只把通过校验的连接交给 frp
type knockListener struct {
	net.Listener
	key   []byte
	ch    chan net.Conn
	errCh chan error
	done  chan struct{}
	sem   chan struct{}
	once  sync.Once
}

func WrapKnockListener(l net.Listener) net.Listener {
	key := knockKey()
	if key == nil {
		return l
	}
	kl := &knockListener{
		Listener: l,
		key:      key,
		ch:       make(chan net.Conn),
		errCh:    make(chan error, 1),
		done:     make(chan struct{}),
		sem:      make(chan struct{}, knockPending),
	}
	go kl.loop()
	return kl
}

func (kl *knockListener) loop() {
	for {
		c, err := kl.Listener.Accept()
		if err != nil {
			kl.errCh <- err
			return
		}
		select {
		case kl.sem <- struct{}{}:
			go kl.check(c)
		default:
			_ = c.Close() // 校验队列已满，直接丢弃
		}
	}
}

func (kl *knockListener) check(c net.Conn) {
	defer func() { <-kl.sem }()
	_ = c.SetReadDeadline(time.Now().Add(knockReadTO))
	buf := make([]byte, knockLen)
	if _, err := io.ReadFull(c, buf); err != nil {
		_ = c.Close()
		return
	}
	ts := int64(binary.BigEndian.Uint64(buf[:knockTSLen]))
	d := time.Since(time.Unix(ts, 0))
	if d < -knockSkew || d > knockSkew ||
		subtle.ConstantTimeCompare(buf[knockTSLen:], knockMAC(kl.key, buf[:knockTSLen])) != 1 {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	select {
	case kl.ch <- c:
	case <-kl.done:
		_ = c.Close()
	}
}

func (kl *knockListener) Accept() (net.Conn, error) {
	select {
	case c := <-kl.ch:
		return c, nil
	case err := <-kl.errCh:
		kl.errCh <- err
		return nil, err
	case <-kl.done:
		return nil, net.ErrClosed
	}
}

func (kl *knockListener) Close() error {
	kl.once.Do(func() { close(kl.done) })
	return kl.Listener.Close()
}
