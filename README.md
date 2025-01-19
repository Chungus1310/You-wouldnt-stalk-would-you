# 👀 You Wouldn't Stalk, Would You? 

A Python-based IP camera scanner for educational purposes that demonstrates async network scanning and camera protocol implementations.🎥

## 🌟 Features

- Async scanning of IP ranges for various camera protocols
- Support for RTSP, HTTP, and VNC camera streams
- Built-in database of common camera manufacturers and models
- Default credential testing (because people still use admin/admin 🤦‍♂️)
- Shodan and ZoomEye integration for extra intel
- Friendly progress tracking and logging
- Circuit breaker pattern to be nice to the networks
- GeoIP lookups for found devices
- ONVIF device discovery
- Detailed hit logging and results export

## 🚀 Getting Started

### Prerequisites

```bash
# Install required packages
pip install -r requirements.txt

# You'll also need:
- Python 3.7+
- OpenCV
```

### Basic Usage

```bash
# Fire it up!
python ipcam_menhera.py
```

## 📝 Configuration

The scanner has some fun knobs you can tweak in the code:

- `WORKER_COUNT`: How many parallel workers (default: 10000)
- `MAX_SOCKETS`: Socket limit per worker (default: 20000)
- `BATCH_SIZE`: IPs per batch (default: 2000)
- Various timeouts and retry settings

## 🎮 How It Works

1. Generates random IPs (avoiding reserved ranges)
2. Scans for open camera-related ports
3. Tests various protocols and default creds
4. Enriches findings with extra data
5. Saves results for your viewing pleasure

## 📦 Project Structure

```
/
├── ipcam_menhera.py     # Main scanner code
├── logs/                # Where the magic gets logged
├── output/              # Discovered devices end up here
└── README.md           # You are here! 👋
```

## 🤝 Contributing

Got ideas? Found a bug? Want to add your camera brand's default URLs? Pull requests welcome!

1. Fork it
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

**THIS IS PURELY FOR EDUCATIONAL PURPOSES!**

This code is:
- Not tested thoroughly
- Probably buggy
- Definitely not production-ready
- Just a demonstration
- Not meant for actual use
- Really, please don't use this for bad things

The creator:
- Takes no responsibility for how this code is used
- Cannot be held liable for any damages
- Seriously hopes you're just here to learn
- Would prefer you use this knowledge for good
- Is probably facepalming if you're using this maliciously

## 🔗 Links

- [Project Homepage](https://github.com/Chungus1310/You-wouldnt-stalk-would-you)
- [Report Bug](https://github.com/Chungus1310/You-wouldnt-stalk-would-you/issues)
- [Request Feature](https://github.com/Chungus1310/You-wouldnt-stalk-would-you/issues)

---

Made with 💖 and questionable decisions by Chungus1310

Remember: Just because you can, doesn't mean you should.
