import pandas
import pandas as pd
from sklearn import preprocessing
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy
from sklearn import svm
from sklearn.model_selection import cross_validate as cv
#changed this package below line
from sklearn import model_selection
import matplotlib.pylab as plt
import warnings
from sklearn.metrics import confusion_matrix

warnings.filterwarnings("ignore", category=DeprecationWarning, module="pandas", lineno=570)


def return_nonstring_col(data_cols):
    cols_to_keep = []
    train_cols = []
    for col in data_cols:
        if col != 'URL' and col != 'host' and col != 'path':
            cols_to_keep.append(col)
            if col != 'malicious' and col != 'result':
                train_cols.append(col)
    return [cols_to_keep, train_cols]

#Support Vector Machine
def svm_classifier(train, query, train_cols):
    clf = svm.SVC()

    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    print(clf.fit(train[train_cols], train['malicious']))
    scores = cv.cross_val_score(clf, train[train_cols], train['malicious'], cv=30)
    print('Estimated score SVM: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    query['result'] = clf.predict(query[train_cols])

    print(query[['URL', 'result']])

#Decision tree classifier
def decision_tree(train, query, train_cols):

    #instantiating the model
    tree = DecisionTreeClassifier(min_impurity_decrease=0)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(tree.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = model_selection.cross_val_score(tree, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Decision Tree Classifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model 
    query['result'] = tree.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Multilayer Perceptrons
def multilayer_perceptron(train, query, train_cols):
    #instantiating the model
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(mlp.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = model_selection.cross_val_score(mlp, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Multilayer Perceptrons: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = mlp.predict(query[train_cols])

    #printing the predicted results  
    print(query[['URL', 'result']])
    return query['result']


#AdaBoost Classifier
def adaboost_classifier(train, query, train_cols):
    #instantiating the model
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    
    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(hybrid_model_AB.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = model_selection.cross_val_score(hybrid_model_AB, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Adaboost Classifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = hybrid_model_AB.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Naive Bayes Classifier
def naivebayes_classifier(train, query, train_cols):
    #instantiating the model
    gnb = GaussianNB()

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(gnb.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = model_selection.cross_val_score(gnb, train[train_cols], train['malicious'], cv=30)
    print('Estimated score for Naive Bayes Classifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = gnb.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Stacking all models into one

#Random forest classifier + Gaussian Naive Bayes
def stackedmodel_a(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    lr = LogisticRegression(solver='lbfgs', max_iter=700)  
    clf_stack = StackingClassifier(classifiers =[rf, gnb], meta_classifier = lr, use_probas = True, use_features_in_secondary = True)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stack.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stack, train[train_cols], train['malicious'], cv=30) 
    print('Estimated score Random Forest & Gaussian Naive Bayes: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stack.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest classifier + Gaussian Naive Bayes+ Decision Tree Classifier
def stackedmodel_b(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    lrx = LogisticRegression(solver='lbfgs', max_iter=800)  
    clf_stackx = StackingClassifier(classifiers =[clf_stack, tree], meta_classifier = lrx, use_probas = True, use_features_in_secondary = True)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackx.fit(train[train_cols], train['malicious'])) 

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackx, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest,Gaussian Naive Bayes & Decision Forest: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackx.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest classifier + Gaussian Naive Bayes+ Decision Tree Classifier + MLPs
def stackedmodel_c(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)

    lry = LogisticRegression(solver='lbfgs', max_iter=500)  
    clf_stacky = StackingClassifier(classifiers =[clf_stackx, mlp], meta_classifier = lry, use_probas = True, use_features_in_secondary = True)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stacky.fit(train[train_cols], train['malicious'])) 

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stacky, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest,Gaussian Naive Bayes,Decision Forest & MLPs: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stacky.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest classifier + Gaussian Naive Bayes+ Decision Tree Classifier + MLPs + AdaBoost
def stackedmodel_d(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    
    lrz = LogisticRegression(solver='lbfgs', max_iter=1000)  
    clf_stackz = StackingClassifier(classifiers =[clf_stacky, hybrid_model_AB], meta_classifier = lrz, use_probas = True, use_features_in_secondary = True)

     #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackz.fit(train[train_cols], train['malicious'])) 

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackz, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest,Gaussian Naive Bayes,Decision Forest,MLPs & AdaBoost: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackz.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest classifier + Gaussian Naive Bayes+ Decision Tree Classifier + MLPs + AdaBoost + SVM
def stackedmodel_e(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    clf = svm.SVC() 

    lrm = LogisticRegression(solver='lbfgs', max_iter=1000)  
    clf_stackm = StackingClassifier(classifiers =[clf_stackz, clf], meta_classifier = lrz, use_probas = True, use_features_in_secondary = True)

     #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackm.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackm, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest,Gaussian Naive Bayes,Decision Forest,MLPs,AdaBoost & SVM: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackm.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']



#Stacking 2 Models with better accuracy rates together

#Gaussian Naive Bayes and Random forest Classifiers
def stackedmodel_m(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()

    lra = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stacka = StackingClassifier(classifiers =[rf, gnb], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

    #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stacka.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stacka, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest & Gaussian Naive Bayes: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stacka.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest and Decision Tree Classifiers
def stackedmodel_n(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    tree = DecisionTreeClassifier(min_impurity_decrease=0)

    lrb = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackb = StackingClassifier(classifiers =[rf, tree], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

     #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackb.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackb, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest & Decision Tree: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackb.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Decision Tree and AdaBoost
def stackedmodel_o(train, query, train_cols):
    #instantiating the model
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)

    lrc = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackc = StackingClassifier(classifiers =[tree, hybrid_model_AB], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

     #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackc.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackc, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Decision Tree and Adaboost: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackc.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']


#Random Forest and AdaBoost
def stackedmodel_p(train, query, train_cols):
    #instantiating the model
    rf = RandomForestClassifier(n_estimators=150)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)

    lrd = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackd = StackingClassifier(classifiers =[rf, hybrid_model_AB], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

     #cleaning data by applying preprocessing
    train[train_cols] = preprocessing.scale(train[train_cols])
    query[train_cols] = preprocessing.scale(query[train_cols])

    #fitting the model
    print(clf_stackd.fit(train[train_cols], train['malicious']))

    #cross-validating and evaluating the performance of model
    scores = cv.cross_val_score(clf_stackd, train[train_cols], train['malicious'], cv=30)
    print('Estimated score Random Forest & Gaussian Naive Bayes: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    #predicting the target query from the model
    query['result'] = clf_stackd.predict(query[train_cols])

    #printing the predicted results
    print(query[['URL', 'result']])
    return query['result']

def tree_gui(train, query, train_cols):
    tree = DecisionTreeClassifier(min_impurity_decrease=0)

    print(tree.fit(train[train_cols], train['malicious']))

    query['result'] = tree.predict(query[train_cols])

    print(query[['URL', 'result']].head(2))
    return query['result']


def multilayer_perceptron_gui(train, query, train_cols):

    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)

    print(mlp.fit(train[train_cols], train['malicious']))
    
    query['result'] = mlp.predict(query[train_cols])
    print(query[['URL', 'result']])
    return query['result']

def adaboost_classifier_gui(train, query, train_cols):
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    
    print(hybrid_model_AB.fit(train[train_cols], train['malicious']))
    
    query['result'] = hybrid_model_AB.predict(query[train_cols])
    print(query[['URL', 'result']])
    return query['result']

def naivebayes_classifier_gui(train, query, train_cols):
    gnb = GaussianNB()

    print(gnb.fit(train[train_cols], train['malicious']))
    
    query['result'] = gnb.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

def svm_classifier_gui(train, query, train_cols):
    clf = svm.SVC()

    print(clf.fit(train[train_cols], train['malicious']))

    query['result'] = clf.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

def stackedmodel_a_gui(train, query, train_cols):

    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()

    lr = LogisticRegression(solver='lbfgs', max_iter=700)  
    clf_stack = StackingClassifier(classifiers =[rf, gnb], meta_classifier = lr, use_probas = True, use_features_in_secondary = True)


    print(clf_stack.fit(train[train_cols], train['malicious']))
   
    query['result'] = clf_stack.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

def stackedmodel_b_gui(train, query, train_cols):

    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)

    lrx = LogisticRegression(solver='lbfgs', max_iter=800)  
    clf_stackx = StackingClassifier(classifiers =[clf_stack, tree], meta_classifier = lrx, use_probas = True, use_features_in_secondary = True)


    print(clf_stackx.fit(train[train_cols], train['malicious']))

    query['result'] = clf_stackx.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

def stackedmodel_c_gui(train, query, train_cols):

    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)

    lry = LogisticRegression(solver='lbfgs', max_iter=500)  
    clf_stacky = StackingClassifier(classifiers =[clf_stackx, mlp], meta_classifier = lry, use_probas = True, use_features_in_secondary = True)

    print(clf_stacky.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stacky.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

def stackedmodel_d_gui(train, query, train_cols):

    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    
    lrz = LogisticRegression(solver='lbfgs', max_iter=1000)  
    clf_stackz = StackingClassifier(classifiers =[clf_stacky, hybrid_model_AB], meta_classifier = lrz, use_probas = True, use_features_in_secondary = True)

    print(clf_stackz.fit(train[train_cols], train['malicious']))

    query['result'] = clf_stackz.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']


def stackedmodel_e_gui(train, query, train_cols):

    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    mlp = MLPClassifier(alpha=0.001, hidden_layer_sizes=([100,100,100]),max_iter=900)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)
    clf = svm.SVC() 

    lrm = LogisticRegression(solver='lbfgs', max_iter=1000)  
    clf_stackm = StackingClassifier(classifiers =[clf_stackz, clf], meta_classifier = lrz, use_probas = True, use_features_in_secondary = True)

    print(clf_stackm.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stackm.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

#Stacking 2 Models with better accuracy rates together

#Gaussian Naive Bayes and Random forest Classifiers

def stackedmodel_m_gui(train, query, train_cols):
    rf = RandomForestClassifier(n_estimators=150)
    gnb = GaussianNB()

    lra = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stacka = StackingClassifier(classifiers =[rf, gnb], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

    print(clf_stacka.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stacka.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

#Random Forest and Decision Tree Classifiers
def stackedmodel_n_gui(train, query, train_cols):
    rf = RandomForestClassifier(n_estimators=150)
    tree = DecisionTreeClassifier(min_impurity_decrease=0)

    lrb = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackb = StackingClassifier(classifiers =[rf, tree], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

    print(clf_stackb.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stackb.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']


#Decision Tree and AdaBoost
def stackedmodel_o_gui(train, query, train_cols):
    tree = DecisionTreeClassifier(min_impurity_decrease=0)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)

    lrc = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackc = StackingClassifier(classifiers =[tree, hybrid_model_AB], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

    print(clf_stackc.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stackc.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']


#Random Forest and AdaBoost
def stackedmodel_p_gui(train, query, train_cols):
    rf = RandomForestClassifier(n_estimators=150)
    hybrid_model_AB = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=10)

    lrd = LogisticRegression(solver='lbfgs', max_iter=300)  
    clf_stackd = StackingClassifier(classifiers =[rf, hybrid_model_AB], meta_classifier = lra, use_probas = True, use_features_in_secondary = True)

    print(clf_stackd.fit(train[train_cols], train['malicious']))
    
    query['result'] = clf_stackd.predict(query[train_cols])

    print(query[['URL', 'result']])
    return query['result']

# Called from gui
def forest_classifier_gui(train, query, train_cols):
    rf = RandomForestClassifier(n_estimators=150)

    print(rf.fit(train[train_cols], train['malicious']))

    query['result'] = rf.predict(query[train_cols])

    print(query[['URL', 'result']].head(2))
    return query['result']


def forest_classifier(train, query, train_cols):
    rf = RandomForestClassifier(n_estimators=150)

    print(rf.fit(train[train_cols], train['malicious']))
    scores = model_selection.cross_val_score(rf, train[train_cols], train['malicious'], cv=30)
    print('Estimated score RandomForestClassifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

    query['result'] = rf.predict(query[train_cols])
    print(query[['URL', 'result']])
    return query['result']


def train(db, test_db):
    query_csv = pandas.read_csv(test_db)
    cols_to_keep, train_cols = return_nonstring_col(query_csv.columns)
    # query=query_csv[cols_to_keep]

    train_csv = pandas.read_csv(db)
    cols_to_keep, train_cols = return_nonstring_col(train_csv.columns)
    train = train_csv[cols_to_keep]

    svm_classifier(train_csv, query_csv, train_cols)
    naivebayes_classifier(train_csv, query_csv, train_cols)
    decision_tree(train_csv, query_csv, train_cols) 
    multilayer_perceptron(train_csv, query_csv, train_cols)
    adaboost_classifier(train_csv, query_csv, train_cols)
    forest_classifier(train_csv, query_csv, train_cols)

    stackedmodel_a(train_csv, query_csv, train_cols)
    stackedmodel_b(train_csv, query_csv, train_cols)
    stackedmodel_c(train_csv, query_csv, train_cols)
    stackedmodel_d(train_csv, query_csv, train_cols)
    stackedmodel_e(train_csv, query_csv, train_cols)
   
    stackedmodel_m(train_csv, query_csv, train_cols)
    stackedmodel_n(train_csv, query_csv, train_cols)
    stackedmodel_o(train_csv, query_csv, train_cols)
    stackedmodel_p(train_csv, query_csv, train_cols)

def gui_caller(db, test_db):
    query_csv = pandas.read_csv(test_db)
    cols_to_keep, train_cols = return_nonstring_col(query_csv.columns)
    # query=query_csv[cols_to_keep]

    train_csv = pandas.read_csv(db)
    cols_to_keep, train_cols = return_nonstring_col(train_csv.columns)
    train = train_csv[cols_to_keep]

    return forest_classifier(train_csv, query_csv, train_cols)
    return naivebayes_classifier(train_csv, query_csv, train_cols)
    return decision_tree(train_csv, query_csv, train_cols)
    return multilayer_perceptron(train_csv, query_csv, train_cols)
    return adaboost_classifier(train_csv, query_csv, train_cols)  
    return svm_classifier(train_csv, query_csv, train_cols)
   

    return stackedmodel_a(train_csv, query_csv, train_cols)
    return stackedmodel_b(train_csv, query_csv, train_cols)
    return stackedmodel_c(train_csv, query_csv, train_cols)
    return stackedmodel_d(train_csv, query_csv, train_cols)
    return stackedmodel_e(train_csv, query_csv, train_cols)

    return stackedmodel_m(train_csv, query_csv, train_cols)
    return stackedmodel_n(train_csv, query_csv, train_cols)
    return stackedmodel_o(train_csv, query_csv, train_cols)
    return stackedmodel_p(train_csv, query_csv, train_cols)
print("trainer is running ...")
