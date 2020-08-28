# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import minmax_scale
#from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier
import pickle
#from sklearn.externals import joblib
import joblib

import warnings

def clf_fnc(arr):

    warnings.filterwarnings('ignore')

    try:
        clf = joblib.load('filename.pkl')
    except:
        dataset = pd.read_csv('Training Dataset.csv')
        # dataset 분리
        X = dataset.iloc[:, 0:29]
        Y = dataset.iloc[:, 29:]
        train_scaled = minmax_scale(X, axis = 0)
        ncol = train_scaled.shape[1] # 29

        (X_train, X_test, y_train_labels, y_test_labels) = train_test_split(train_scaled, 
                                                            Y, test_size=0.3, random_state=np.random.seed(172))

        clf = RandomForestClassifier(max_depth=30, criterion='gini')
        clf.fit(X_train, y_train_labels)
        saved_model = pickle.dumps(clf)
        joblib.dump(clf, 'filename.pkl') 
        #------ modle save code

    a=np.array(arr).reshape(1,29)

    result = clf.predict(a)
    print(result)
    #----- predict result from load model
    return result
