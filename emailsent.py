from email.message import EmailMessage
import smtplib
import ssl
import towstepverification
import time

def send_otp_email(receiver_email, otp):
        sender_email = "fycopractice@gmail.com"
        sender_password = "hqxf dpdw tjpj xtqu"
        subject = "Your OTP for Job Sphere"
        body = f"Your OTP is: {otp}"

        em = EmailMessage()
        em['From'] = sender_email
        em['To'] = receiver_email
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(sender_email, sender_password)
                smtp.sendmail(sender_email, receiver_email, em.as_string())


if __name__ == "__main__":
        receiver_email = input("Enter your email: ")
        otp = towstepverification.generate_otp()
        send_otp_email(receiver_email, otp)
        print("You have 30 seconds to enter the OTP.")
        start_time = time.time()
        user_otp = None
        expired = False
        while True:
            user_otp = input("Enter the OTP sent to your email: ")
            elapsed = time.time() - start_time
            if elapsed > 30:
                print("OTP expired. Please try again.")
                # Optionally, send expiry email
                send_otp_email(receiver_email, "Your OTP has expired. Please request a new one.")
                expired = True
                break
            else:
                break

        if expired:
            print("OTP expired.")
            pass
        elif towstepverification.verify_otp(user_otp):
            print("OTP verified. Login successful!")
        else:
            print("Invalid OTP. Login failed.")
