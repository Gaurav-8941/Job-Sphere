
import pyotp

key = "NOTSOEASYTODECODEISITHUHLOLQWERTYUIOP"
totp = pyotp.TOTP(key)

def generate_otp():
	"""Generate a TOTP code."""
	return totp.now()

def verify_otp(otp):
	"""Verify a TOTP code, allowing a small time window for delays."""
	return totp.verify(otp, valid_window=1)
 

