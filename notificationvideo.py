from email.message import EmailMessage
import smtplib
import ssl

def send_video_email(receiver_emailnotify):
        sender_email = "fycopractice@gmail.com"
        sender_password = "hqxf dpdw tjpj xtqu"
        subject = "Video Call Job Sphere"
        body = f"Hr is contacting you for video call. Please check your profile page"
        em = EmailMessage()
        em['From'] = sender_email
        em['To'] = receiver_emailnotify
        em['Subject'] = subject
        em.set_content(body)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(sender_email, sender_password)
                smtp.sendmail(sender_email, receiver_emailnotify, em.as_string())
        print("Email sent successfully.")
if __name__ == "__main__":
        receiver_emailnotify = "fycopractice@gmail.com"
        send_video_email(receiver_emailnotify)