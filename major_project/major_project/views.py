from django.shortcuts import render
import tkinter as tk 
from tkinter import messagebox,simpledialog,filedialog
from tkinter import *
import tkinter
from imutils import paths
from tkinter.filedialog import askopenfilename
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import cross_val_score
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
from sklearn.model_selection import train_test_split,KFold,cross_val_score,GridSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier

import warnings

def button(request):
    return render(request,'home.html')
def output(request):
    warnings.filterwarnings('ignore')

    root= tk.Tk() 
    root.title("Network Intrusion Detection")
    root.geometry("1300x1200")


    def upload_data():
        global filename
        filename = askopenfilename(initialdir = "Dataset")
        text.insert(END,"Dataset loaded\n\n")


    def data():
        global filename
        global df
        text.delete('1.0',END)
        df = pd.read_csv(filename)
        text.insert(END,"Complete Dataset\n\n")
        text.insert(END,df)    
        return df

    def statistics():    
        global df
        text.delete('1.0',END)   
        text.insert(END,"Top FIVE rows of the Dataset\n\n")
        text.insert(END,df.head())    
        stats=df.describe()
        text.insert(END,"\n\nStatistical Measurements for Data\n\n")
        text.insert(END,stats)
        

    def preprocess():
        global df
        text.delete('1.0',END)
        df = df.drop(['protocol_type','service','flag'],axis=1)
        df=df.loc[:, (df==0).mean() < .7]
        df['label'] = df['label'].map({'anomaly':1,'normal':0})
        text.insert(END,"\t\t\tPreprocessed Data\n\n")
        text.insert(END,df)
        

    def train_test():
        global df
        global x_train, x_test, y_train, y_test
        text.delete('1.0',END)
        x=df.iloc[:,:-1]
        y=df.iloc[:,-1]
        x_train,x_test,y_train,y_test=train_test_split(x,y,test_size=0.2,random_state=25)    
        text.insert(END,"Train and Test model Generated\n\n")
        text.insert(END,"Total Dataset Size : "+str(len(df))+"\n")
        text.insert(END,"Training Size : "+str(len(x_train))+"\n")
        text.insert(END,"Test Size : "+str(len(x_test))+"\n")
        return x_train,x_test,y_train,y_test


    # Machine Learning Models

    def RF():
        global x_train,x_test,y_train,y_test
        global new_x_train,new_x_test
        text.delete('1.0',END)
        text.insert(END,"\t\t\t\tRandom Forest Classifier\n\n")
        model= RandomForestClassifier(random_state=25)
        model= model.fit(x_train,y_train)
        features = pd.DataFrame()
        features['Feature'] = x_train.columns
        features['Importance'] = model.feature_importances_
        features.sort_values(by=['Importance'], ascending=False, inplace=True)
        text.insert(END,"Selected Important Features by *feature_importances_* & *SelectFromModel*\n\n")
        selector = SelectFromModel(model, prefit=True)
        train_reduced = selector.transform(x_train)
        columns=x_train.columns[selector.get_support()]
        new_x_train=pd.DataFrame(train_reduced,columns=columns)
        test_reduced = selector.transform(x_test)
        new_x_test=pd.DataFrame(test_reduced,columns=columns)   
        rf = RandomForestClassifier(random_state=25)
        rf.fit(new_x_train, y_train)
        pred=rf.predict(new_x_test)
        acc=accuracy_score(y_test,pred)
        cm=confusion_matrix(y_test,pred)
        CR=classification_report(y_test,pred)
        output = rf.predict(new_x_test).astype(int)
        df_output = pd.DataFrame()    
        df_output['Network_Intrusion_Predicted'] = np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(output)
        final_pred=pd.concat([new_x_test,df_output],axis=1 )
        final_pred.to_csv('Network_Prediction_submission@RF.csv',index=False)
        text.insert(END,features[:5])
        text.insert(END,"\n\nConfusion Matrix:\n"+str(cm)+"\n\n")
        text.insert(END,"Accuracy Score:\n"+str(np.round(acc*100,4))+' %'+"\n\n")
        text.insert(END,"Predicted Values on Test Data:\n"+str(pred)+"\n\n")
        text.insert(END,"Classification Report:\n"+str(CR))
        text.insert(END,"\n\nFinal Predicted values on New Data:\n\n")
        text.insert(END,final_pred)
        text.insert(END,"\n\nCheck the Project Directory for Submission CSV file\n\n")
        text.insert(END,"@@@------------------Thank You--------------------@@@")
        

    def KNN():
        global x_train,x_test,y_train,y_test
        global new_x_train,new_x_test,new_data
        text.delete('1.0',END)
        text.insert(END,"\t\t\t\tLogistic Regression\n\n")
        model = KNeighborsClassifier()
        model.fit(new_x_train, y_train)
        pred=model.predict(new_x_test)
        acc=accuracy_score(y_test,pred)
        cm=confusion_matrix(y_test,pred)
        CR=classification_report(y_test,pred)
        text.insert(END,"\n\nConfusion Matrix:\n"+str(cm)+"\n\n")
        text.insert(END,"Accuracy:\n"+str(np.round(acc*100,4))+' %'+"\n\n")
        text.insert(END,"Predicted Values on Test Data:\n"+str(pred)+"\n\n")
        text.insert(END,"Classification Report:\n"+str(CR))
        output = model.predict(new_x_test).astype(int)
        df_output = pd.DataFrame()    
        df_output['Network_Intrusion_Predicted'] = np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(output)
        final_pred=pd.concat([new_x_test,df_output],axis=1 )
        final_pred.to_csv('Network_Prediction_submission@KNN.csv',index=False)
        text.insert(END,"\n\nFinal Predicted values on New Data:\n\n")
        text.insert(END,final_pred)
        text.insert(END,"\n\nCheck the Project Directory for Submission CSV file\n\n")
        text.insert(END,"@@@------------------Thank You--------------------@@@")

    def DT():
        global x_train,x_test,y_train,y_test
        global new_x_train,new_x_test,new_data
        text.delete('1.0',END)
        text.insert(END,"\t\t\t\tDecision Tree Classifier\n\n")
        model = DecisionTreeClassifier()
        model.fit(new_x_train, y_train)
        pred=model.predict(new_x_test)
        acc=accuracy_score(y_test,pred)
        cm=confusion_matrix(y_test,pred)
        CR=classification_report(y_test,pred)
        text.insert(END,"\n\nConfusion Matrix:\n"+str(cm)+"\n\n")
        text.insert(END,"Accuracy:\n"+str(np.round(acc*100,4))+' %'+"\n\n")
        text.insert(END,"Predicted Values on Test Data:\n"+str(pred)+"\n\n")
        text.insert(END,"Classification Report:\n"+str(CR))
        output = model.predict(new_x_test).astype(int)
        df_output = pd.DataFrame()    
        df_output['Network_Intrusion_Predicted'] = np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(output)
        final_pred=pd.concat([new_x_test,df_output],axis=1 )
        final_pred.to_csv('Network_Prediction_submission@DT.csv',index=False)
        text.insert(END,"\n\nFinal Predicted values on New Data:\n\n")
        text.insert(END,final_pred)
        text.insert(END,"\n\nCheck the Project Directory for Submission CSV file\n\n")
        text.insert(END,"@@@------------------Thank You--------------------@@@")


    def input_values():
        text.delete('1.0',END)
        global x_train,x_test,y_train,y_test
        global new_x_train,new_x_test

        global src_bytes 
        src_bytes = float(entry1.get()) 
        
        global dst_bytes  
        dst_bytes = float(entry2.get())

        global dst_host_srv_count  
        dst_host_srv_count = float(entry3.get())

        global same_srv_rate
        same_srv_rate = float(entry4.get())

        global dst_host_same_srv_rate 
        dst_host_same_srv_rate  = float(entry5.get())
        
        list1=[[src_bytes,dst_bytes,dst_host_srv_count,same_srv_rate,dst_host_same_srv_rate]]

        dt = DecisionTreeClassifier(random_state=25)
        dt.fit(new_x_train, y_train)

        Prediction_result  = dt.predict(list1)
        if list1[0][0]==0:
            text.insert(END,"Decision Tree Classifier having greater accuracy score\n\n")
            text.insert(END,"New values are predicted from Decision Tree Classifier\n\n")
            text.insert(END,"Predicted Network Intrusion Status for the New inputs\n\n")
            text.insert(END,np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(Prediction_result))
        elif list1[0][0]==1:
            text.insert(END,"Random Forest Classifier having greater accuracy score\n\n")
            text.insert(END,"New values are predicted from Random Forest Classifier\n\n")
            text.insert(END,"Predicted Network Intrusion Status for the New inputs\n\n")
            text.insert(END,np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(Prediction_result))
        else:
            text.insert(END,"KNeighbours Classifier having greater accuracy score\n\n")
            text.insert(END,"New values are predicted from KNeighbours Classifier\n\n")
            text.insert(END,"Predicted Network Intrusion Status for the New inputs\n\n")
            text.insert(END,np.vectorize(lambda s: 'Anomaly' if s==1 else 'Normal')(Prediction_result))
    font = ('times', 14, 'bold')
    title = Label(root, text='Network Intrusion Detection Using Machine Learning')  
    title.config(font=font)           
    title.config(height=2, width=120)       
    title.place(x=0,y=5)

    font1 = ('times',13 ,'bold')
    button1 = tk.Button (root, text='Upload Data',width=13,command=upload_data) 
    button1.config(font=font1)
    button1.place(x=60,y=100)

    button2 = tk.Button (root, text='Read Data',width=13,command=data)
    button2.config(font=font1)
    button2.place(x=60,y=150)

    button3 = tk.Button (root, text='Statistics',width=13,command=statistics)  
    button3.config(font=font1)
    button3.place(x=60,y=200)

    button3 = tk.Button (root, text='Preprocessing',width=13,command=preprocess)
    button3.config(font=font1) 
    button3.place(x=60,y=250)

    button4 = tk.Button (root, text='Train & Test',width=13,command=train_test)
    button4.config(font=font1) 
    button4.place(x=60,y=300)

    title = Label(root, text='Application of ML models') 
    title.config(font=font1)           
    title.config(width=25)       
    title.place(x=250,y=70)

    button5 = tk.Button (root, text='Random Forest',width=15,bg='pale green',command=RF)
    button5.config(font=font1) 
    button5.place(x=300,y=100)

    button6 = tk.Button (root, text='KNN',width=15,bg='sky blue',command=KNN)
    button6.config(font=font1) 
    button6.place(x=300,y=150)

    button7 = tk.Button (root, text='Decision Tree',width=15,bg='orange',command=DT)
    button7.config(font=font1) 
    button7.place(x=300,y=200)



    title = Label(root, text='Enter Input values for the New Prediction')
    title.config(bg='black', fg='white')  
    title.config(font=font1)           
    title.config(width=40)       
    title.place(x=60,y=380)


    def clear1(event):
        entry1.delete(0, tk.END)

    font2=('times',10)
    entry1 = tk.Entry (root) # create 1st entry box
    entry1.config(font=font2)
    entry1.place(x=60, y=450,height=30,width=150)
    entry1.insert(0,'src_bytes')
    entry1.bind("<FocusIn>",clear1)

    def clear2(event):
        entry2.delete(0, tk.END)

    font2=('times',10)
    entry2 = tk.Entry (root) # create 1st entry box
    entry2.config(font=font2)
    entry2.place(x=315, y=450,height=30,width=150)
    entry2.insert(0,'dst_bytes')
    entry2.bind("<FocusIn>",clear2)


    def clear3(event):
        entry3.delete(0, tk.END)

    font2=('times',10)
    entry3 = tk.Entry (root) # create 1st entry box
    entry3.config(font=font2)
    entry3.place(x=60, y=500,height=30,width=150)
    entry3.insert(0,'dst_host_srv_count')
    entry3.bind("<FocusIn>",clear3)

    def clear4(event):
        entry4.delete(0, tk.END)

    font2=('times',10)
    entry4 = tk.Entry (root) # create 1st entry box
    entry4.config(font=font2)
    entry4.place(x=315, y=500,height=30,width=150)
    entry4.insert(0,'same_srv_rate')
    entry4.bind("<FocusIn>",clear4)

    def clear5(event):
        entry5.delete(0, tk.END)

    font2=('times',10)
    entry5 = tk.Entry (root) # create 1st entry box
    entry5.config(font=font2)
    entry5.place(x=60, y=550,height=30,width=150)
    entry5.insert(0,'dst_host_same_srv_rate')
    entry5.bind("<FocusIn>",clear5)





    Prediction = tk.Button (root, text='Prediction',width=15,fg='white',bg='green',command=input_values)
    Prediction.config(font=font1) 
    Prediction.place(x=180,y=650)



    font1 = ('times', 11, 'bold')
    text=Text(root,height=32,width=90)
    scroll=Scrollbar(text)
    text.configure(yscrollcommand=scroll.set,xscrollcommand=scroll.set)
    text.place(x=550,y=70)
    text.config(font=font1)

    #root.config(bg='grey')
    root.mainloop()
    return render(request,'home.html')
    #alt+click
