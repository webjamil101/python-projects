Here are all the `pip install` commands for the imported libraries in your code:

## Core Requirements
```bash
pip install pyttsx3
pip install SpeechRecognition
pip install wikipedia-api
pip install pyautogui
pip install pyjokes
pip install beautifulsoup4
pip install psutil
pip install pygame
pip install opencv-python
pip install python-vlc
pip install yt-dlp
pip install Pillow
pip install google-api-python-client
pip install google-auth-oauthlib
pip install pycaw
pip install wakeonlan
pip install cryptography
pip install requests
pip install pytz
pip install scipy
pip install sympy
pip install scapy
```

## Optional/Alternative Installs

### For better speech recognition (optional):
```bash
pip install pyaudio  # For microphone access
```

### For Google Calendar API:
```bash
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

### For advanced features:
```bash
pip install numpy  # Often needed for OpenCV and other scientific computing
pip install matplotlib  # For plotting (if you add visualization features)
```

## Platform-Specific Notes

### Windows:
```bash
# Most packages should work as-is on Windows
```

### macOS:
```bash
# You might need to install portaudio for pyaudio
brew install portaudio
pip install pyaudio
```

### Linux (Ubuntu/Debian):
```bash
# First install system dependencies
sudo apt update
sudo apt install python3-pyaudio portaudio19-dev libasound2-dev libjack-dev
sudo apt install python3-opencv libcairo2-dev libgirepository1.0-dev
sudo apt install vlc libvlc-dev

# Then install Python packages
pip install pyaudio
```

## Installation Script

You can create a requirements.txt file with this content:

```txt
pyttsx3==2.90
SpeechRecognition==3.10.0
wikipedia-api==0.5.8
pyautogui==0.9.54
pyjokes==0.6.0
beautifulsoup4==4.12.2
psutil==5.9.6
pygame==2.5.2
opencv-python==4.8.1.78
python-vlc==3.0.18122
yt-dlp==2023.11.16
Pillow==10.1.0
google-api-python-client==2.108.0
google-auth-oauthlib==1.1.0
pycaw==20200807
wakeonlan==3.0.0
cryptography==41.0.7
requests==2.31.0
pytz==2023.3
scipy==1.11.3
sympy==1.12
scapy==2.5.0
```

Then install with:
```bash
pip install -r requirements.txt
```

## Troubleshooting Tips

1. **If `pyaudio` fails to install**, use:
   ```bash
   pip install pipwin
   pipwin install pyaudio
   ```

2. **For VLC issues**, make sure VLC media player is installed on your system.

3. **Admin privileges** might be needed for some audio/video packages.

4. **Virtual environment** recommended to avoid conflicts:
   ```bash
   python -m venv voice_assistant_env
   source voice_assistant_env/bin/activate  # Linux/macOS
   voice_assistant_env\Scripts\activate    # Windows
   ```

Let me know if you encounter any specific installation issues!
