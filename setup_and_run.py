import os
import sys
import platform
import subprocess
import shutil
import argparse
import time
import signal
import atexit
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def is_command_available(command):
    """Check if a command is available in the system path."""
    return shutil.which(command) is not None

def install_ollama():
    """Install Ollama based on OS."""
    system = platform.system().lower()
    
    logger.info("Installing Ollama...")
    try:
        if system == "linux":
            subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, check=True)
        elif system == "darwin":  # macOS
            subprocess.run("brew install ollama", shell=True, check=True)
        elif system == "windows":
            subprocess.run("irm https://ollama.com/install.ps1 | iex", shell=True, check=True)
        else:
            logger.error(f"Unsupported operating system: {system}")
            sys.exit(1)
        logger.info("Ollama installed successfully.")
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to install Ollama: {str(e)}")
        sys.exit(1)

def is_ollama_server_running():
    """Check if Ollama server is responding."""
    try:
        response = requests.get("http://localhost:11434/api/version", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False

def start_ollama_server():
    """Start the Ollama server and wait for it to be ready."""
    logger.info("Starting Ollama server...")
    
    system = platform.system().lower()
    
    if system == "windows":
        server_process = subprocess.Popen(
            ["start", "/b", "ollama", "serve"],
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    else:  # unix
        with open(os.devnull, 'w') as devnull:
            server_process = subprocess.Popen(
                ["ollama", "serve"],
                stdout=devnull,
                stderr=devnull,
                start_new_session=True
            )
    
    logger.info("Waiting for Ollama server to start...")
    max_retries = 30  # Maximum number of retries (30 × 2 seconds = 60 seconds max wait time)
    retries = 0
    
    while retries < max_retries:
        if is_ollama_server_running():
            logger.info("✓ Ollama server is now running")
            return server_process
        time.sleep(2)
        retries += 1
        if retries % 5 == 0:
            logger.info(f"Still waiting for Ollama server... ({retries}/{max_retries})")
    
    logger.error("Timed out waiting for Ollama server to start")
    sys.exit(1)

def check_model_exists(model_name):
    """Check if the specified model exists in Ollama."""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=10)
        if response.status_code == 200:
            models = response.json().get("models", [])
            return any(model.get("name") == model_name for model in models)
        return False
    except requests.RequestException:
        return False

def pull_model(model_name):
    """Pull the specified model using Ollama with progress updates."""
    logger.info(f"Checking if model {model_name} is available...")
    
    if check_model_exists(model_name):
        logger.info(f"✓ Model {model_name} is already available")
        return
    
    logger.info(f"Pulling {model_name} model. This may take a while...")
    
    try:
        process = subprocess.Popen(
            ["ollama", "pull", model_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        last_update = time.time()
        logger.info("Starting download (this may take several minutes)...")
        
        for line in process.stdout:
            current_time = time.time()
            if current_time - last_update > 5:
                logger.info(f"Still downloading: {line.strip()}")
                last_update = current_time
        
        process.wait()
        
        if process.returncode != 0:
            logger.error(f"Failed to pull model: exit code {process.returncode}")
            sys.exit(1)
            
        logger.info(f"✓ {model_name} model pulled successfully.")
    except Exception as e:
        logger.error(f"Error during model download: {str(e)}")
        logger.info("You may need to manually download the model with 'ollama pull mistral:7b'")
        logger.info("Then run this script again.")
        sys.exit(1)

def install_python_dependencies():
    """Install Python dependencies from requirements.txt."""
    logger.info("Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        logger.info("✓ Python dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Vulnerability Analysis Tool')
    parser.add_argument('--cve', type=str, required=True, help='CVE ID to analyze')
    args = parser.parse_args()
    
    try:
        # Try importing dependency as a check
        import requests
    except ImportError:
        logger.info("Installing required Python dependencies...")
        install_python_dependencies()
    
    if not is_command_available("ollama"):
        logger.info("Ollama is not installed. Installing now...")
        install_ollama()
    else:
        logger.info("✓ Ollama is already installed.")

    server_process = None
    if not is_ollama_server_running():
        logger.info("Ollama server is not running. Starting now...")
        server_process = start_ollama_server()
        
        # Cleanup function to stop the server when script exits
        def cleanup():
            if server_process:
                logger.info("Stopping Ollama server...")
                try:
                    if platform.system().lower() == "windows":
                        subprocess.run(["taskkill", "/f", "/im", "ollama.exe"], check=False)
                    else:
                        os.killpg(os.getpgid(server_process.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError) as e:
                    logger.error(f"Error stopping Ollama server: {e}")
        
        atexit.register(cleanup)
    else:
        logger.info("✓ Ollama server is already running.")
    
    model_name = "mistral:7b"
    pull_model(model_name)
    
    logger.info(f"Running analysis for CVE {args.cve}...")
    try:
        result = subprocess.run([sys.executable, "main.py", "--cve", args.cve], check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        logger.error(f"Analysis failed: {e}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(130)