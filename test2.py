import serial

ser = serial.serial_for_url('loop://1', baudrate=9600, bytesize=8, parity="E", stopbits=2, rtscts=False, dsrdtr=False, timeout=5)
ser.write(b'Teste teste teste teste')

ser.close()