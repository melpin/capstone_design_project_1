from flask import Flask, request, jsonify
import sys
import features_optimization
import time

app = Flask(__name__)

@app.route('/')
def index():
	return "test"

@app.route('/keyboard')
def Keyboard():
	dataSend = {
		'type': 'buttons',
		'buttons': ['대화하기']
	}
	return jsonify(dataSend)	


@app.route('/message', methods=['POST'])
def Message():
	content = request.get_json()
	user_input_url = content['action']['detailParams']['sys_url']['value']

	print(user_input_url, file=sys.stdout)

	result = features_optimization.parse_url(content)
	if result == 1:
		res = {
		  "version": "2.0",
		  "template": {
		    "outputs": [
		      {
		        "basicCard": {
		          "title": "피싱사이트입니다!",
		          "description": "입력하신 사이트 "+user_input_url+" 는 피싱사이트입니다!",
		          "thumbnail": {
		            "imageUrl": "https://postfiles.pstatic.net/MjAyMDA2MjJfOTEg/MDAxNTkyNzU0ODY0MTA3.4y7ZfdgiapyvpfuIiwq0ZOpco0MSSwAD238yaOoS_dgg.eab8PDlhQ2PsfThtlePx7WQGzsP47QAD_y3mYzu7M_og.PNG.hwangju7476/12red.png?type=w773"
		          },
		          "profile": {
		            "imageUrl": "https://postfiles.pstatic.net/MjAyMDA2MjJfOTEg/MDAxNTkyNzU0ODY0MTA3.4y7ZfdgiapyvpfuIiwq0ZOpco0MSSwAD238yaOoS_dgg.eab8PDlhQ2PsfThtlePx7WQGzsP47QAD_y3mYzu7M_og.PNG.hwangju7476/12red.png?type=w773",
		            "nickname": "프로파일 닉네임"
		          }
		        }
		      }
		    ]
		  }
		}
	else:
		res = {
		  "version": "2.0",
		  "template": {
		    "outputs": [
		      {
		        "basicCard": {
		          "title": "안전한 사이트입니다",
		          "description": "입력하신 사이트 "+user_input_url+" 는 안전합니다.",
		          "thumbnail": {
		            "imageUrl": "https://postfiles.pstatic.net/MjAyMDA2MjJfMTM3/MDAxNTkyNzUyMjQ1NTU2.WhkrGiaQIll3rur9LOC_oqumwWMqLUXoNEij7hV81mUg.6wDZxUTkRXqXCkgqEdY00y07-m4mvCbNmLf5b4A7xB0g.PNG.hwangju7476/12green.png?type=w773"
		          },
		          "profile": {
		            "imageUrl": "https://postfiles.pstatic.net/MjAyMDA2MjJfMTM3/MDAxNTkyNzUyMjQ1NTU2.WhkrGiaQIll3rur9LOC_oqumwWMqLUXoNEij7hV81mUg.6wDZxUTkRXqXCkgqEdY00y07-m4mvCbNmLf5b4A7xB0g.PNG.hwangju7476/12green.png?type=w773",
		            "nickname": "프로파일 닉네임"
		          }
		        }
		      }
		    ]
		  }
		}

	return jsonify(res)

if __name__ == '__main__':
	app.run(host='0.0.0.0', port="10000", threaded=True)

