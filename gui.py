from tkinter import *
import tkinter.messagebox as tkMessageBox
import trainer as tr
import webbrowser
import pandas
import main

root = Tk()
root.title("Malicious Url Detector")
img = PhotoImage(width=500,height=300)
root.attributes('-alpha',0.92)
root.iconbitmap('malware.ico')
root.configure(background='lavender')
root.geometry("750x120")
frame = Frame(root, bg ="lavender")
frame.pack(ipady=10)
bottomframe = Frame(root, bg="lavender")
bottomframe.pack(side=BOTTOM, ipady=5)

L1 = Label(frame, text="Enter the URL: ", font=("Arial Bold",9),bg="lavender", padx=5, pady=5)
L1.pack(side=LEFT)
E1 = Entry(frame, bd=4,highlightcolor="black",highlightbackground="black", width=140,bg="lavender",fg="black")
E1.pack(side=RIGHT)


def submitCallBack():
    url = E1.get()
    main.process_test_url(url, 'test_features.csv')
    return_ans = tr.gui_caller('url_features.csv', 'test_features.csv')
    a = str(return_ans).split()
    print("-----")
    print("return_ans:",return_ans)
    print("-----")
    if int(a[1]) == 0:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Safe to Visit")
        new=1
        answer = tkMessageBox.askquestion("Redirect","Do you want to visit the url?")
        if answer == 'yes':
                chrome_path = 'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe %s'
                webbrowser.get(chrome_path).open(url=E1.get(),new=1)
    elif int(a[1]) == 1:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Malicious")
        answer_2 = tkMessageBox.askquestion("Redirect", "The url MALICIOUS, Do you still want to visit the url?")
        if answer_2=='yes':
            webbrowser.open(url=E1.get(),new=1)
    else:
        tkMessageBox.showinfo("URL Checker Result", "The URL " + url + " is Malware")
        tkMessageBox.showwarning("Warning","Cant Redirect, url contains a malware")

def about():
    tkMessageBox.showinfo("About","The tool classifies the URL as Safe or Malicious or Malware based on AI.\nAuthors: Nikhitha & Deepanvi")

B1 = Button(bottomframe, text="Submit",font=("Arial bold",9),command=submitCallBack, bg="purple", fg="snow")
B1.pack(side=RIGHT, padx=0,pady=0)

B2 = Button(root, text="About", command=about,font=("Arial bold",9),bg="purple", fg="snow")
B2.pack(side=RIGHT, padx=10, pady=0)

root.mainloop()


