# NetRecon
# NetRecon

A simple local network reconnaissance tool. It scans a given subnet and detects which hosts are active.

## Features

- Subnet validation (network address, broadcast address, total IP count)
- Automatic scan: pings all hosts in the subnet in parallel
- Manual mode: check a single IP by hand
- Active/inactive host detection

## Usage

```bash
python3 netrecon.py
```

The program will ask you, in order:
1. An IP/subnet (e.g. `192.168.1.0/24`)
2. Whether you want an automatic or manual scan

## Disclaimer

This tool is intended to be used **only on networks you own or have explicit permission to test.** Scanning networks without authorization may carry legal consequences.

## Roadmap

- [ ] DNS access history check (on your own device)
- [ ] Port scanning

---

# NetRecon (Türkçe)

Basit bir yerel ağ keşif (network reconnaissance) aracı. Girilen subnet üzerinde aktif host'ları tespit eder.

## Özellikler

- Subnet doğrulama (network/broadcast adresi, toplam IP sayısı)
- Otomatik tarama: subnet'teki tüm host'ları paralel ping ile tarar
- Manuel mod: tek bir IP'yi elle kontrol etme
- Aktif/pasif host tespiti

## Kullanım

```bash
python3 netrecon.py
```

Program seni sırayla şunları sormaya çalışacak:
1. IP/subnet (örn: `192.168.1.0/24`)
2. Otomatik mi manuel mi taramak istediğin

## Uyarı

Bu araç yalnızca **kendi sahip olduğun veya izin aldığın ağlarda** kullanılmak üzere yapılmıştır. Başkasına ait ağlarda izinsiz tarama yasal sorumluluk doğurabilir.

## Yol Haritası

- [ ] DNS erişim geçmişi kontrolü (kendi cihaz üzerinden)
- [ ] Port tarama
