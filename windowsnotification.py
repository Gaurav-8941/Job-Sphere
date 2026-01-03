from plyer import notification
import time
def notify_video_call(title,message):
    title = title
    message = message
    app_icon_path = "D:\\Job Sphere\\static\\Job Sphere.ico" # Must be a .ico file on Windows
    notification.notify(
        title=title,
        message=message,
        app_icon=app_icon_path,
        timeout=10,
    )
    time.sleep(10) 
if __name__ == "__main__":
        title = "Job Sphere Notification"
        message = "Hr has initiated a video call. Please check your profile page."
        notify_video_call(title, message)
