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
def notify_video_call_hr(title,message_hr):
    title = title
    message_hr = message_hr
    app_icon_path = "D:\\Job Sphere\\static\\Job Sphere.ico" # Must be a .ico file on Windows
    notification.notify(
        title=title,
        message=message_hr,
        app_icon=app_icon_path,
        timeout=10,
    )
    time.sleep(10) 
if __name__ == "__main__":
        title = "Job Sphere Notification"
        message = "Hr has initiated a video call. Please check your profile page."
        message_hr="Candidate has joined the video call. Please proceed."
        notify_video_call(title, message)
        notify_video_call_hr(title, message_hr)
