#  Install these libraries on your machine:
# pip install pyQt5
# pip install pandas scikit-learn
# pip install pywintrace
# pip install etw
# pip install pywin32

import ctypes
import sys
import time
import pandas as pd
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QWidget, QHBoxLayout, QMessageBox
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QFont
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import win32evtlog

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    # Your existing code goes here
    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()

            self.setWindowTitle('Ransomware Detection')
            self.setGeometry(200, 200, 800, 400)

            # Set the font for the application
            font = QFont("Arial", 12, QFont.Bold)
            self.setFont(font)

            # Set the main layout
            main_layout = QVBoxLayout()

            # Title label
            title_label = QLabel('Dynamic Ransomware Detection System')
            title_label.setFont(QFont("Arial", 16, QFont.Bold))
            title_label.setStyleSheet("color: #3498987db;")
            title_label.setAlignment(Qt.AlignCenter)
            main_layout.addWidget(title_label)

            # Status label
            self.label = QLabel('Click "Start Detection" to begin monitoring')
            self.label.setFont(QFont("Arial", 14))
            self.label.setAlignment(Qt.AlignCenter)
            main_layout.addWidget(self.label)

            # Button layout
            button_layout = QHBoxLayout()
            
            # Start button
            self.start_button = QPushButton('Start Detection')
            self.start_button.setStyleSheet("background-color: #2e6771; color: white;")
            self.start_button.clicked.connect(self.start_detection)
            button_layout.addWidget(self.start_button)

            # Stop button
            self.stop_button = QPushButton('Stop Detection')
            self.stop_button.setStyleSheet("background-color: #e7489c6c; color: white;")
            self.stop_button.clicked.connect(self.stop_detection)
            self.stop_button.setEnabled(False)
            button_layout.addWidget(self.stop_button)

            main_layout.addLayout(button_layout)

            # Container widget
            container = QWidget()
            container.setLayout(main_layout)
            self.setCentralWidget(container)

            # Set up a timer to simulate real-time data collection
            self.timer = QTimer()
            self.timer.timeout.connect(self.collect_and_detect)
            
            # Load the trained model
            self.model = self.train_model()

            # Placeholder for system call monitor process
            self.monitor_process = None
            self.system_calls = []

        def start_detection(self):
            self.start_system_call_monitoring()  # Start the system call monitor
            self.timer.start(10000)  # Collect data every 10 seconds
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.label.setText('Monitoring for ransomware activity...')
            self.label.setStyleSheet("color: #f1c405423f;")

        def stop_detection(self):
            self.timer.stop()
            self.stop_system_call_monitoring()  # Stop the system call monitor
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.label.setText('Detection stopped.')
            self.label.setStyleSheet("color: #e74c3c;")

        def collect_and_detect(self):
            print("Collecting and detecting...")
            if not self.system_calls:
                print("No system calls collected.")
                self.label.setText("No system calls collected.")
                return
            
            # Use the collected system call data
            for call in self.system_calls:
                print(f"Processing system call: {call}")
                new_data = {
                    'timestamp': [time.strftime('%Y-%m-%d %H:%M:%S')],
                    'syscall': [call['syscall']],
                    'arguments': [call['arguments']],
                    'hour': [time.localtime().tm_hour],
                    'day': [time.localtime().tm_mday],
                    'weekday': [time.localtime().tm_wday]
                }
                df = pd.DataFrame(new_data)
                X_new = pd.get_dummies(df[['hour', 'day', 'weekday', 'syscall', 'arguments']])
                
                # Ensure the new data has the same features as the training data
                X_new = X_new.reindex(columns=self.X_columns, fill_value=0)

                # Measure detection time
                start_time = time.time()
                prediction = self.model.predict(X_new)
                end_time = time.time()
                detection_time = end_time - start_time

                # Update the GUI with the prediction result and detection time
                if prediction[0] == 1:
                    result = "Ransomware detected!"
                    self.label.setStyleSheet("color: #e74c3c;")
                    self.show_alert("Warning", result)
                else:
                    result = "No ransomware detected"
                    self.label.setStyleSheet("color: #2ecc71;")
                
                self.label.setText(f"{result} (Detection time: {detection_time:.4f} seconds)")
                print(f"Predicted: {result}, Detection Time: {detection_time:.4f} seconds")
            
            # Clear the collected system calls after processing
            self.system_calls = []

        def train_model(self):
            # Example DataFrame with system call data
            data = {
                'timestamp': ['2024-07-11 10:00:00', '2024-07-11 10:05:00', '2024-07-11 10:10:00', '2024-07-11 10:15:00'],
                'syscall': ['open', 'read', 'write', 'open'],
                'arguments': ['file1.txt', 'file2.txt', 'file3.txt', 'malicious_file.exe'],
                'label': [0, 1, 0, 1]  # 0: benign, 1: ransomware
            }
            df = pd.DataFrame(data)

            # Extract time features
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            df['day'] = pd.to_datetime(df['timestamp']).dt.day
            df['weekday'] = pd.to_datetime(df['timestamp']).dt.weekday

            # Select features and target
            features = ['hour', 'day', 'weekday', 'syscall', 'arguments']
            X = pd.get_dummies(df[features])
            y = df['label']

            # Save the feature columns for later use
            self.X_columns = X.columns

            # Split data into training and test sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

            # Train the model
            model = RandomForestClassifier()
            model.fit(X_train, y_train)

            # Evaluate the model
            y_pred = model.predict(X_test)
            print(classification_report(y_test, y_pred, zero_division=1))
            print(confusion_matrix(y_test, y_pred))

            return model

        def start_system_call_monitoring(self):
            self.server = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            self.handles = []
            self.handles.append((self.server, flags))
            print("System call monitoring started.")

        def stop_system_call_monitoring(self):
            for handle, flags in self.handles:
                win32evtlog.CloseEventLog(handle)
            self.handles = []
            print("System call monitoring stopped.")

        def etw_callback(self):
            for handle, flags in self.handles:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                for evt in events:
                    syscall = evt.SourceName
                    arguments = evt.StringInserts
                    if arguments:
                        arguments = " ".join(arguments)
                    else:
                        arguments = ""
                    self.system_calls.append({'syscall': syscall, 'arguments': arguments})
                    print(f"Collected system call: {syscall}, arguments: {arguments}")

        def show_alert(self, title, message):
            alert = QMessageBox()
            alert.setWindowTitle(title)
            alert.setText(message)
            alert.setIcon(QMessageBox.Warning)
            alert.exec_()

    if __name__ == '__main__':
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
