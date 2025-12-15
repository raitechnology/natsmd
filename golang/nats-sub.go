package main

/*
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <raimd/md_msg.h>
#include <raimd/rv_msg.h>
#include <raimd/dict_load.h>
*/
import "C"

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/nats-io/nats.go"
)

/*func find_field(field string, rd *C.MDFieldReader_t) bool {
  return C.md_field_reader_find(rd, (*C.char)(unsafe.Pointer(&[]byte(field)[0])), C.size_t(len(field))));
}*/

func print_real(field string, rd *C.MDFieldReader_t) bool {
  /* get a real and a decimal from the price */
  var prc C.double
  if (C.md_field_reader_get_real(rd, (unsafe.Pointer)(&prc), (C.size_t)(unsafe.Sizeof(prc)))) {
    fmt.Printf("%s: real: %f\n", field, prc)
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_uint(field string, rd *C.MDFieldReader_t) bool {
  /* get a real and a decimal from the price */
  var uval C.uint64_t
  if (C.md_field_reader_get_uint(rd, (unsafe.Pointer)(&uval), (C.size_t)(unsafe.Sizeof(uval)))) {
    fmt.Printf("%s: uint: %d\n", field, uval)
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_int(field string, rd *C.MDFieldReader_t) bool {
  /* get a real and a decimal from the price */
  var ival C.int64_t
  if (C.md_field_reader_get_uint(rd, (unsafe.Pointer)(&ival), (C.size_t)(unsafe.Sizeof(ival)))) {
    fmt.Printf("%s: int: %d\n", field, ival)
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_decimal(field string, rd *C.MDFieldReader_t) bool {
  var dec C.MDDecimal_t
  if (C.md_field_reader_get_decimal(rd, &dec)) {
    var buf [64]byte
    C.md_decimal_get_string(&dec, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), false)
    fmt.Printf("%s: decimal: %s\n", field, string(buf[:]))
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_string(field string, rd *C.MDFieldReader_t) bool {
  /* get a string into a go buffer */
  var buf [1024]byte
  buflen := C.size_t(len(buf));
  if (C.md_field_reader_get_string_buf(rd, (*C.char)(unsafe.Pointer(&buf[0])), buflen, &buflen)) {
    fmt.Printf("%s: string: \"%s\"\n", field, string(buf[:]))
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_date(field string, rd *C.MDFieldReader_t) bool {
  /* get a string into a go buffer */
  if (! C.md_field_reader_find(rd, (*C.char)(unsafe.Pointer(&[]byte(field)[0])), C.size_t(len(field)))) {
    return false
  }
  var dt C.MDDate_t
  if (C.md_field_reader_get_date(rd, &dt)) {
    var buf [64]byte
    C.md_date_get_string(&dt, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), C.MD_DATE_FMT_MMM_dd_yyyy)
    fmt.Printf("%s: date: %s\n", field, string(buf[:]))
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func print_time(field string, rd *C.MDFieldReader_t) bool {
  var tm C.MDTime_t
  if (C.md_field_reader_get_time(rd, &tm)) {
    var buf [64]byte
    C.md_time_get_string(&tm, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
    fmt.Printf("%s: time: %s\n", field, string(buf[:]))
    return true
  }
  fmt.Printf("%s failed\n", field)
  return false
}

func main() {
	// Command-line flags
	serverURL := flag.String("server", nats.DefaultURL, "NATS server URL (default: nats://localhost:4222)")
	queueGroup := flag.String("queue", "", "Queue group name (optional)")
	showTimestamp := flag.Bool("timestamp", false, "Show timestamp with each message")
	dictRpc := flag.Bool("dict", false, "Request dict with rpc")
	flag.Parse()

	// Get subjects from remaining arguments
	subjects := flag.Args()
	if len(subjects) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <subject1> [subject2] ...\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s foo.bar\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -server nats://demo.nats.io:4222 foo.>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -queue workers -timestamp task.*\n", os.Args[0])
		os.Exit(1)
	}

	// Connect to NATS, the _bin tells the server to use binary message formatting
	nc, err := nats.Connect(*serverURL, nats.Name( "subscribe_bin" ))
	if err != nil {
		log.Fatalf("Failed to connect to NATS server at %s: %v", *serverURL, err)
	}
	defer nc.Close()

	fmt.Printf("Connected to NATS server at %s\n", *serverURL)

	var dict *C.MDDict_t
	var mem *C.MDMsgMem_t
	C.md_msg_mem_create(&mem)

	if *dictRpc {
		// Make RPC request to DICT subject before subscribing
		fmt.Println("Making RPC request to 'DICT' subject...")
		msg, err := nc.Request("_TIC.REPLY.SASS.DATA.DICTIONARY", []byte(""), 5*time.Second)
		if err != nil {
			if err == nats.ErrTimeout {
				log.Fatalf("RPC request to 'DICT' timed out after 5 seconds\n")
			}
			log.Fatalf("RPC request to 'DICT' failed: %v\n", err)
		}
		fmt.Printf("Received DICT response (%d bytes):\n\n", len(msg.Data))

		/*
		var mout *C.MDOutput_t
		C.md_output_init(&mout)
		*/
		// Get C.uint8_t pointer from msg.Data
		if len(msg.Data) > 0 {
			// Get pointer to the first byte of the Go slice
			cBuffer := (unsafe.Pointer(&msg.Data[0]))
			cLen := C.size_t(len(msg.Data))

			// Now you can pass cBuffer and cLen to C functions
			// Example: Call C functions from raimd library here
			C.md_msg_mem_reuse(mem)
			tibmsg := C.md_msg_unpack(cBuffer, 0, cLen, 0, nil, mem)
			if (tibmsg == nil) {
			  log.Fatalf("Unable to unpack DICT response\n")
			}
			dict = C.md_load_sass_dict(tibmsg)
		}
	} else {
		dict = nil
	}
	// Message handler
	msgHandler := func(msg *nats.Msg) {
		if *showTimestamp {
			fmt.Printf("[%s] ", time.Now().Format("2006-01-02 15:04:05.000"))
		}
		fmt.Printf("[%s]  ", msg.Subject)
		cBuffer := (unsafe.Pointer(&msg.Data[0]))
                cLen := C.size_t(len(msg.Data))
		C.md_msg_mem_reuse(mem)
		mdmsg := C.md_msg_unpack(cBuffer, 0, cLen, 0, dict, mem)
		if ( mdmsg == nil ) {
			fmt.Printf("failed\n")
			log.Printf("Unable to unpack message\n")
		} else {
			fmt.Printf("fmt %s\n", C.GoString(C.md_msg_get_proto_string(mdmsg)))
			rd := C.md_msg_get_field_reader(mdmsg);
			/*
			C.md_msg_print(mdmsg, mout)
			C.md_output_flush(mout)
			*/
			nm := (*C.MDName_t)(C.malloc(C.sizeof_MDName_t))
			defer C.free(unsafe.Pointer(nm))
			for b := C.md_field_reader_first(rd, nm); b; b = C.md_field_reader_next(rd, nm) {
				fname := C.GoString(nm.fname)
				switch C.md_field_reader_type(rd) {
				case C.MD_UINT:
					print_uint(fname, rd)
				case C.MD_INT:
					print_int(fname, rd)
				case C.MD_REAL:
					print_real(fname, rd)
				case C.MD_DECIMAL:
					print_decimal(fname, rd)
				case C.MD_DATE:
					print_date(fname, rd)
				case C.MD_TIME:
					print_time(fname, rd)
				case C.MD_STRING:
					fallthrough
				default:
					print_string(fname, rd)
				}
			}
			os.Stdout.Sync()
		}
	}

	// Subscribe to all subjects
	var subs []*nats.Subscription
	var mu sync.Mutex

	for _, subject := range subjects {
		var sub *nats.Subscription
		var err error

		if *queueGroup != "" {
			sub, err = nc.QueueSubscribe(subject, *queueGroup, msgHandler)
			fmt.Printf("Subscribed to '%s' with queue group '%s'\n", subject, *queueGroup)
		} else {
			sub, err = nc.Subscribe(subject, msgHandler)
			fmt.Printf("Subscribed to '%s'\n", subject)
		}

		if err != nil {
			log.Fatalf("Failed to subscribe to '%s': %v", subject, err)
		}

		mu.Lock()
		subs = append(subs, sub)
		mu.Unlock()
	}

	// Flush to ensure subscriptions are processed
	if err := nc.Flush(); err != nil {
		log.Fatalf("Failed to flush connection: %v", err)
	}

	fmt.Println("\nListening for messages... (Press Ctrl+C to exit)")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")

	// Unsubscribe from all subjects
	mu.Lock()
	for _, sub := range subs {
		sub.Unsubscribe()
	}
	mu.Unlock()

	fmt.Println("Disconnected from NATS server")
}
