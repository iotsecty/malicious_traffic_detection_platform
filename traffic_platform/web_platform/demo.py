
"""
作者：byack
email：18788748257@163.com
"""

# 导入flask包和一些需要的扩展
from flask import Flask, render_template, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
import sqlite3

# 创建flask的应用程序
app = Flask(__name__)
app.config["SECRET_KEY"] = '123456'
# 用bootstrap来渲染这个app
bootstrap = Bootstrap(app)

# 一个存储城市点击量的字典
city_num = {"杭州": 0, "西安": 0, "北京": 0, "青岛": 0, "郑州": 0, "香港": 0, "澳门": 0, 
            "黄山": 0, "济南": 0, "张家界": 0, "乌镇": 0, "南昌": 0, "哈尔滨": 0, "千岛湖": 0, 
            "三亚": 0, "丽江": 0, "香格里拉": 0, "威海": 0, "大理": 0, "济宁": 0, "五台山": 0,
            "武夷山": 0, "普陀山": 0, "马鞍山": 0, "烟台": 0, "桃花岛": 0, "普吉岛": 0, "都江堰": 0,
            "井冈山": 0, "聊城": 0}

# 这是主页面，用来欢迎和说明本网站的一些内容
@app.route('/')
def welcome():
    txt = open("welcome.txt")
    text = txt.read()
    txt.close
    return render_template("welcome.html", text = text)

# 这是用于收集用户喜欢城市数据的页面
class Cityform(FlaskForm):
    username = StringField(u'你叫啥子名字哦？ ', validators=[DataRequired()])
    region1 = StringField(u'你最喜欢的城市是哪鸭！ ', validators=[DataRequired()])
    region2 = StringField(u'除了上面个还有其它的吗？', validators=[DataRequired()])
    region3 = StringField(u'一定还有吧！快说', validators=[DataRequired()])
    region4 = StringField(u'再说一个呗，快！', validators=[DataRequired()])
    region5 = StringField(u'我保证这是我问你的最后一个了！', validators=[DataRequired()])
    submit = SubmitField('提交')

@app.route('/WriteDate', methods=['GET', 'POST'])
def write_date():
    city_form = Cityform()
    # print(request.form.get('username'))
    if request.method == 'POST':
        username = request.form.get('username')
        region1 = request.form.get('region1')
        region2 = request.form.get('region2')
        region3 = request.form.get('region3')
        region4 = request.form.get('region4')
        region5 = request.form.get('region5')
        if city_form.validate_on_submit():
            city_num[region1] += 1
            city_num[region2] += 1
            city_num[region3] += 1
            city_num[region4] += 1
            city_num[region5] += 1
            conn = sqlite3.connect('travel_date.db')
            curs = conn.cursor()
            query = 'INSERT INTO travel_date VALUES(?,?,?,?,?,?)'
            vals = [username, region1, region2, region3, region4, region5]
            curs.execute(query, vals)
            conn.commit()
            curs.close()
            conn.close()
            return render_template("thankyou.html")
    return render_template("write_date.html", form=city_form)

# 这是显示分析图表的页面
@app.route("/CatDate")
def cat_date():
    top_date = []
    temp = list(city_num.values())
    temp.sort(reverse=True)
    temp = temp[:10]
    for i, j in city_num.items():
        if j in temp:
            top_date.append([i, j])
    top_date.sort(key=lambda x:x[1])
    top_date.reverse()        
    return render_template("cat_date.html", date=top_date)

# 主函数，开始运行程序
if __name__ == "__main__":
    # 每一次运行前， 都将数据库中的值读出放入点击量的字典中
    conn = sqlite3.connect('travel_date.db')
    curs = conn.cursor()
    dates = curs.execute('SELECT region1, region2, region3, region4, region5 from travel_date')
    for i in dates:
        for j in range(5):
            city_num[i[j]] += 1
    curs.close()
    conn.close()
    
    app.run(debug=True)