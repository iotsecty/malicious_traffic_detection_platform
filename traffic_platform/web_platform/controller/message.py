import os
# from web_platform import db
from flask import request,render_template,flash,abort,url_for,redirect,session,Flask
from werkzeug.utils import secure_filename
# import sys
# sys.path.append('...')
from ...train_test.main import analysis
from ...web_platform import app
# # 数据库方案需导入文件
# from platform.model.User import  User
# from platform.model.Category import Category

@app.route('/')
def upload():
    return render_template('upload.html')

@app.route('/error',methods=['POST','GET'])
def show_error():
    if request.method == 'POST':
        return render_template('upload.html')
    else:
        return render_template('show_error.html')

@app.route('/detection',methods = ['POST','GET'])
def upload_file():
    error=None
    if request.method == 'POST':
        f = request.files["file"]
        ftype=secure_filename(f.filename).split('.')[-1]
        if ftype!='pcap':
            # error='Invalid filetype'
            flash ('请检查文件类型是否正确！')
            return  redirect(url_for('show_error'))
        else:
            pcap_save_path=os.path.join(app.config['UPLOAD_FOLDER'],secure_filename(f.filename))
            csv_sava_path=os.path.join(app.config['UPLOAD_FOLDER'],'result.csv')
            f.save(pcap_save_path)
            # # ===========MySQL存储方案（待完成）===================
            # category = Category(username,filename)
            # db.session.add(category)
            # db.session.commit()
            # session['upload']=True
            flash('upload file is successfully saved !')
            # return "upload file is successful!"
            if analysis(pcap_save_path,csv_sava_path,num_epoch=5,num_ev=20):
                return  'The file is safe'
            else:
                return 'The file is dangerous'
            # 后续需要更改此处的逻辑，以更加合适的方式返回！！！！
            return redirect(url_for('detection'))
    
## ===================用户注册/登录/注销操作（待完成）====================================
# @app.route('/login',methods=['GET','POST'])
# def login():
#     error = None
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         user = User.query.filter_by(username=request.form['username']).first()
#         passwd = User.query.filter_by(password=request.form['password']).first()

#         if user is None:
#             error = 'Invalid username'
#         elif passwd is None:
#             error = 'Invalid password'
#         else:
#             session['logged_in'] = True
#             flash('You were logged in')
#             return redirect(url_for('show_entries'))
#     return render_template('login.html', error=error)

# @app.route('/add',methods=['POST'])
# def add_entry():
#     if not session.get('logged_in'):
#         abort(401)
#     title = request.form['title']
#     content = request.form['text']
#     category = Category(title,content)
#     db.session.add(category)
#     db.session.commit()
#     flash('New entry was successfully posted')
#     return redirect(url_for('show_entries'))


# @app.route('/logout')
# def logout():
#     session.pop('logged_in', None)
#     flash('You were logged out')
#     return redirect(url_for('show_entries'))
