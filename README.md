Detail paket :


1	0.000000	192.168.1.50	224.0.0.252	LLMNR	62	Unknown operation (9) 0x4c4c[Malformed Packet]
2	1.000000	192.168.1.200	192.168.1.50	LLMNR	85	Unknown operation (9) 0x4c4c[Malformed Packet]
3	2.000000	192.168.1.50	192.168.1.200	TCP	54	55555 → 445 [SYN] Seq=0 Win=8192 Len=0
4	3.000000	192.168.1.200	192.168.1.50	TCP	54	445 → 55555 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0
5	4.000000	192.168.1.50	192.168.1.200	TCP	54	55555 → 445 [ACK] Seq=1 Ack=1 Win=8192 Len=0
6	5.000000	192.168.1.200	192.168.1.50	NBSS	138	NBSS Continuation Message
7	6.000000	aa:bb:cc:dd:ee:ff	Broadcast	ARP	42	Gratuitous ARP for 192.168.1.1 (Reply)
8	7.000000	aa:bb:cc:dd:ee:ff	CIMSYS_33:44:55	ARP	42	192.168.1.1 is at aa:bb:cc:dd:ee:ff
9	8.000000	192.168.1.200	192.168.1.50	DHCP	316	DHCP Offer    - Transaction ID 0x3903f326
10	9.000000	192.168.1.200	192.168.1.50	DHCP	310	DHCP ACK      - Transaction ID 0x3903f326


Paket : 1. 0.000000	192.168.1.50	224.0.0.252	LLMNR	62	Unknown operation (9) 0x4c4c[Malformed Packet]\
		Protokol: LLMNR (Link-Local Multicast Name Resolution)
		Tujuan: 224.0.0.252 → alamat multicast standar LLMNR
		Isi: Permintaan name resolution (mirip DNS query, tapi broadcast di LAN)
		“Unknown operation (9)” & [Malformed Packet]: artinya struktur datanya rusak — 
		kemungkinan dihasilkan oleh tool attack seperti Responder atau mitm6, yang memanipulasi field LLMNR untuk memancing balasan.
		
		Kemungkinan:
		Ini adalah bait (umpan) untuk memulai serangan LLMNR/NBT-NS Poisoning (MITRE ATT&CK T1557.001 / T1557.002) — 
		attacker mencoba membuat host lain menjawab query palsu agar bisa menangkap hash NTLMv2.

	2. 1.000000	192.168.1.200	192.168.1.50	LLMNR	85	Unknown operation (9) 0x4c4c[Malformed Packet]
		Protokol: LLMNR Response
		Dari: 192.168.1.200 (attacker)
		Ke: 192.168.1.50 (korban)
		Isi: Balasan palsu atas query LLMNR di paket #1.

		Interpretasi keamanan:
		Attacker berpura-pura menjadi host tujuan (misalnya server file) dan mengembalikan jawaban palsu, agar korban percaya bahwa 192.168.1.200 adalah 
		server yang sah → menyebabkan credential hash korban dikirim ke attacker (LLMNR Poisoning).
	
	3. 2.000000	192.168.1.50	192.168.1.200	TCP	54	55555 → 445 [SYN] Seq=0 Win=8192 Len=0
		Port 445 (SMB) → digunakan untuk file sharing Windows.
		Korban (50) mencoba membuat koneksi ke “server palsu” (200).
		TCP 3-way handshake dimulai (SYN).

		Indikasi:
		Koneksi SMB terbentuk akibat poisoning. Korban mencoba melakukan SMB(server Messege Block) authentication ke attacker.
	
	4. 3.000000	192.168.1.200	192.168.1.50	TCP	54	445 → 55555 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0
		Balasan SYN-ACK dari attacker → handshake tahap kedua.
		Menunjukkan bahwa host 192.168.1.200(attacker) menerima koneksi SMB.

		Makna keamanan:
		Attacker berhasil menipu client agar membuat sesi SMB ke dirinya, memungkinkan pencurian NTLM (NT Lan Manager) hash = Paswd hash.

	5. 4.000000	192.168.1.50	192.168.1.200	TCP	54	55555 → 445 [ACK] Seq=1 Ack=1 Win=8192 Len=0
		ACK terakhir → TCP handshake selesai.
		Koneksi SMB terbentuk antara korban dan attacker.

		Setelah ini biasanya akan muncul: 
		Session Setup Request → di mana kredensial NTLMv2 dikirim.
		Jadi, paket ini menandakan fase sebelum hash user dikirim ke attacker.

	6. 5.000000	192.168.1.200	192.168.1.50	NBSS	138	NBSS Continuation Message
		NBSS (NetBIOS Session Service) → layer transport untuk SMB.
		“Continuation Message” berarti data SMB sedang dikirim.

		Makna keamanan:
		Bagian ini kemungkinan berisi response palsu SMB dari attacker untuk memicu autentikasi korban.
		Dengan tool seperti Responder, attacker akan menerima hash NTLMv2 di tahap ini.

	7. 6.000000	aa:bb:cc:dd:ee:ff	Broadcast	ARP	42	Gratuitous ARP for 192.168.1.1 (Reply)
		Gratuitous ARP = ARP Reply tanpa request.
		Tujuan broadcast → semua perangkat di LAN menerima.
		Mengatakan “192.168.1.1 ada di MAC aa:bb:cc:dd:ee:ff”.

		Makna keamanan:
		Attacker sedang melakukan ARP Spoofing / ARP Poisoning (T1557.002) — 
		berpura-pura menjadi gateway (192.168.1.1) agar lalu lintas jaringan korban diarahkan lewat attacker.

	8. 7.000000	aa:bb:cc:dd:ee:ff	CIMSYS_33:44:55	ARP	42	192.168.1.1 is at aa:bb:cc:dd:ee:ff
		ARP Reply ke perangkat tertentu (CIMSYS_33:44:55).
		Memperkuat manipulasi tabel ARP.

		Makna keamanan:
		Konfirmasi dari fase lanjutan ARP spoofing, memastikan host target mempercayai alamat MAC palsu attacker untuk gateway.

	9. 8.000000	192.168.1.200	192.168.1.50	DHCP	316	DHCP Offer    - Transaction ID 0x3903f326
		DHCP Offer dikirim dari 192.168.1.200 (attacker) ke korban.
		Offer berisi konfigurasi IP palsu (gateway, DNS, subnet).

		Makna keamanan:
		Ini bagian dari DHCP Spoofing (MITRE T1557.003) — 
		attacker membuat rogue DHCP server untuk memberikan konfigurasi jaringan palsu agar traffic diarahkan melalui dirinya (MITM).

	10. 9.000000	192.168.1.200	192.168.1.50	DHCP	310	DHCP ACK      - Transaction ID 0x3903f326
		DHCP ACK → mengonfirmasi bahwa korban menerima konfigurasi dari server attacker.
		Setelah ini, korban resmi menggunakan gateway palsu dari attacker.

		Dampak keamanan:
		Semua traffic korban bisa diarahkan ke attacker.
		Kombinasi LLMNR + ARP + DHCP spoofing = full MITM scenario.


Skenario pengecekan :

- LLMNR query (victim 192.168.1.50) and LLMNR response (attacker 192.168.1.200)
- SMB handshake and SMB-like NTLMSSP_AUTH payload (attacker)
- ARP gratuitous reply and ARP reply (attacker claiming gateway 192.168.1.1)
- DHCP OFFER and DHCP ACK from rogue DHCP server 192.168.1.200 offering IP 192.168.1.60 to victim

Wireshark filters:
- LLMNR: llmnr || udp.port == 5355
- SMB: tcp.port == 445
- ARP: arp
- DHCP/BOOTP: bootp || dhcp
- Show traffic between victim and attacker: ip.addr == 192.168.1.50 && ip.addr == 192.168.1.200

