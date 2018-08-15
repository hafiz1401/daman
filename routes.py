from flask import render_template, flash, redirect, url_for, request, session
from app import app, mongo, photos
from app.forms import LoginForm, RegistrationForm, EditProfileForm, ODPForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from werkzeug.urls import url_parse
from datetime import datetime
from collections import defaultdict
from flask import send_file
from flask import jsonify
import os
from werkzeug.security import generate_password_hash, check_password_hash
import re
import time
import csv
import bcrypt
from flask_paginate import Pagination, get_page_parameter

def isunicode(x):
    if isinstance(x, unicode):
        x = x.encode('utf8')
    else:
        x = x
    return x

@app.route('/')
@app.route('/index')
def index():
	if 'username' in session:
		if session['acc_type'] == 'valdat':
			return redirect(url_for('list_odp'))
		elif session['acc_type'] == 'rfs':
			return redirect(url_for('odp_to_uim'))
		elif session['acc_type'] == 'admin':
			return redirect(url_for('list_odp'))
	else:
		return redirect(url_for('login'))
	# return render_template('index.html', title="Home", posts=posts)

@app.route('/login', methods=['GET','POST'])
def login():
	form = LoginForm()
	if request.method == 'POST':
		# if form.validate_on_submit():
		user = mongo.db.datauser
		login_user = user.find_one({'name': request.form['usr']})
		if login_user:
			if bcrypt.hashpw(request.form['pwd'].encode('utf8'), login_user['password'].encode('utf8')) == login_user['password'].encode('utf8'):
				session['username'] = login_user['name']
				session['acc_type'] = login_user['account_type']
				return redirect(url_for('index'))
		return 'Invalid username/password'
	return render_template('login.html', title="Sign In", form=form, session=session )

# 	user_obj = User()
# 	if current_user.is_authenticated:
# 		return redirect(url_for('index'))
# 	form = LoginForm()
# 	if form.validate_on_submit():
# 		user = mongo.db.datax
# 		user_log = user.find_one({'name': form.username.data})
# 		if user_log is None or not User.validate_login(user_log['password'],form.password.data):
# 			flash('Invalid username or password')
#       		return redirect(url_for('login'))		
# 		user_obj = User(user_log['name'])
#     	login_user(user_obj, remember=form.remember_me.data)
#     	next_page = request.args.get('next')
#     	return redirect(url_for('index'))
#     	# if not next_page or url_parse(next_page).netloc != '':
#     		# next_page = url_for('index')
# 		# return redirect(next_page)
		
	
@app.route('/logout')
def logout():
	# logout_user()
	session.pop('username', None)
	session.pop('acc_type', None)
	return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
	if 'acc_type' in session:
		if session['acc_type'] == 'admin':
			form = RegistrationForm()
			if request.method == 'POST':
				# if form.validate_on_submit():
				user = mongo.db.datauser
				existing_user = user.find_one({'name': request.form['usr']})
				if existing_user is None:
					hashpass = bcrypt.hashpw(request.form['pwd'].encode('utf8'), bcrypt.gensalt())
					user.insert({'name': request.form['usr'], 'password': hashpass,'email': request.form['email'], 'account_type': request.form['acc_type']})
					# session['username'] = request.form['usr']
					flash('You are now registered.')
					return redirect(url_for('index'))
				return 'Username already exist'
			return render_template('register.html', title='Register', form=form)
	return redirect(url_for('index'))
# @app.route('/user/<username>')
# @login_required
# def user(username):
# 	user = mongo.db.datax
# 	userx = user.find_one({'name': form.username.data})
# 	return render_template('user.html', user=userx)

# @app.before_request
# def berfore_request():
# 	if current_user.is_authenticated:
# 		# current_user.last_seen = datetime.utcnow()
# 		# db.session.commit()
# 		print ''

# @app.route('/edit_profile', methods=['GET', 'POST'])
# # @login_required
# def edit_profile():
# 	form = EditProfileForm(current_user.username)
# 	if form.validate_on_submit():
# 		current_user.username = form.username.data
# 		current_user.about_me = form.about_me.data
# 		db.session.commit()
# 		flash('Your changes have been saved.')
# 		return redirect(url_for('edit_profile'))
# 	elif request.method == 'GET':
# 		form.username.data = current_user.username
# 		form.about_me.data = current_user.about_me
# 	return render_template('edit_profile.html', title='Edit Profile', form=form)



@app.route('/data_odp/<path:odp>', methods=['GET', 'POST'])
# @login_required
def data_odp(odp):
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		form = ODPForm()
		data = mongo.db.dataodpmaster.find_one({ 'NAMAODP':  odp })
		lis = []
		if data:

			# kap = request.form['kap']
			# kap = len(re.findall('PORT',''.join(data.keys())))
			idx = re.findall(r'PORT_\d+',''.join(data.keys()))
			nport = len(idx)
			kap = []
			usd = []
			for each in idx:
				tmp = re.sub('PORT_','',each)
				kap.append(tmp)
				usd.append(data[each].get('STATUS'))
			# for each in idx:
				# key = 'PORT_'+str(each+1)
				lis.append(
					[data[each].get('LABEL_PORT'),
					data[each].get('STATUS'),
					data[each].get('MODEM'),
					data[each].get('NO_LAYANAN'),
					data[each].get('LABEL_DROPCORE'),
					'PORT'+str(tmp),
					'STATUS'+str(tmp),
					'MODEM'+str(tmp),
					'NOLAYANAN'+str(tmp),
					'DROPCORE'+str(tmp),
					tmp])

			lis.sort(key=lambda x:float(x[10]))
			kap.sort(key=lambda x:float(x[0]))
			# print kap
			kap = str(','.join(kap))
			# print kap
			state = 'old'
			used = usd.count('USED')
			try:
				occu = float(used)/float(nport)*100
			except:
				occu = ''
			r1 = r".{0,3}\-.{0,3}\-[^/]{0,3}"
			try:
				odc = re.search(r1, odp).group(0)
				odc = odc.replace('ODP','ODC')
			except:
				odc = ''
			r2 = r"-.{0,3}"
			try:
				sto = re.search(r2, odp).group(0).replace('-','')
			except:
				sto = ''
			
			batulicin = ["BLC","PLE","PLI","BTB","STI","STU","TKS","PGT","BLN","KTB","TRJ","KPL","STI"]
			tanjung = ["RTA","KDG","PGN","BNG","KGN","NEG","BRI","AMT","PAR","TTG","TJT","TJL"]
			banjarbaru = ["LUL","LDU","BBR","BJB","MTP","MRB"]
			banjarmasin = ["KYG","ULI","BJM","KYI","ULN","GBT","GMB"]
			if sto in batulicin:
				datel = 'BATULICIN'
			elif sto in tanjung:
				datel = 'TANJUNG'
			elif sto in banjarbaru:
				datel = 'BANJARBARU'
			elif sto in banjarmasin:
				datel = 'BANJARMASIN'
			else:
				datel = ''
			try:
				nama_odp = data['_id'].replace('/','-')
				list_foto = os.listdir(os.getcwd()+'\\app\\static\\img')
				res_foto =  [i for i in list_foto if str(nama_odp) in i]
				print res_foto
			except:
				res_foto = []
			if session['acc_type'] == 'valdat':
				return render_template('input_data.html', title='Data ODP', form=form, data=data, lis=lis, datel=datel,res_foto=res_foto, kap = kap, nport = nport, used = used, occu = occu, odc=odc, sto=sto)
			elif session['acc_type'] == 'rfs':
				return render_template('rfs_data.html', title='Data ODP', form=form, data=data, lis=lis, datel=datel,res_foto=res_foto, kap = kap, nport = nport, used = used, occu = occu, odc=odc, sto=sto)
			elif session['acc_type'] == 'admin':
				return render_template('input_data.html', title='Data ODP', form=form, data=data, lis=lis, datel=datel,res_foto=res_foto, kap = kap, nport = nport, used = used, occu = occu, odc=odc, sto=sto)
		else:
			kap = 8

@app.route('/data_odp_new', methods=['GET', 'POST'])
def data_odp_new():
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		if session['acc_type'] == 'admin' or  session['acc_type'] == 'valdat':
			form = ODPForm()
			data = []
			lis = []
			for each in range(8):
				lis.append(['','IDLE','','','','PORT'+str(each+1),'STATUS'+str(each+1),'MODEM'+str(each+1),'NOLAYANAN'+str(each+1),'DROPCORE'+str(each+1),str(each+1)])
			kap = '1,2,3,4,5,6,7,8'
			state= 'new'
			nport = 8
			return render_template('input_data.html', title='Data ODP', form=form, data=data, lis=lis, kap=kap, nport=nport)
		return redirect(url_for('index'))

@app.route('/data_odp/update', methods=['POST'])
def update():
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		if request.method == 'POST':
			forunset = []
			odp_target = request.form['odp_target'].upper()
			aktual_odp = request.form['aktual_odp'].upper()
			tgl_survei = request.form['tgl_survei']
			onsite = request.form['onsite'].upper()
			ondesk = request.form['ondesk'].upper()
			longlat = request.form['longlat']
			port_olt = request.form['port_olt'].upper()
			kap = request.form['kap']
			label_odp = request.form['label_odp'].upper()
			alamat = request.form['alamat'].upper()
			kendala = request.form['kendala'].upper()
			kapx = request.form['kapx']
			# used = request.form['used']
			# occu = request.form['occu']
			# sto = request.form['sto']
			# odc = request.form['odc']
			# datel = request.form['datel']
			tanggal_uim = request.form['tanggal_uim']
			uim = request.form['uim'].upper()
			eksekutor = request.form['eksekutor'].upper()

			
			usd = []

			PORT = defaultdict(dict)
			kapport = re.sub(r'u|\[|\]|\'','',kapx)
			kapport = kapport.split(',')
			kapport = filter(None, kapport)
			kapport.sort(key=lambda x:float(x))
			for each in kapport:
				x = str(each.strip())
				
				lport = 'PORT_'+x
				portx = 'PORT'+x
				statusx = 'STATUS'+x
				modemx = 'MODEM'+x
				nolayananx = 'NOLAYANAN'+x
				dropcorex = 'DROPCORE'+x
				# port.append(request.form[portx])
				# status.append(request.form[statusx])
				# nolayanan.append(request.form[nolayananx])
				# dropcore.append(request.form[dropcorex])
				# PORT[lport]['LABEL_PORT'] = request.form[lport]
				xx = request.form[lport]		
				# print x
				# print xx
				PORT['PORT_'+xx]['LABEL_PORT'] = request.form[portx].upper()	
				PORT['PORT_'+xx]['STATUS'] = request.form[statusx]
				usd.append(request.form[statusx])
				PORT['PORT_'+xx]['MODEM'] = request.form[modemx].upper()
				PORT['PORT_'+xx]['NO_LAYANAN'] = request.form[nolayananx]
				PORT['PORT_'+xx]['LABEL_DROPCORE'] = request.form[dropcorex].upper()
				if x!=xx:
					forunset.append('PORT_'+x)


			used = str(usd.count('USED'))
			try:
				occu = str(float(used)/float(kap)*100)+'%'
			except:
				occu = ''
			r1 = r".{0,3}\-.{0,3}\-[^/]{0,3}"
			try:
				odc = re.search(r1, odp_target).group(0)
				odc = odc.replace('ODP','ODC')
			except:
				odc = ''
			r2 = r"-.{0,3}"
			try:
				sto = re.search(r2, odp_target).group(0).replace('-','')
			except:
				sto = ''
			
			batulicin = ["BLC","PLE","PLI","BTB","STI","STU","TKS","PGT","BLN","KTB","TRJ","KPL","STI"]
			tanjung = ["RTA","KDG","PGN","BNG","KGN","NEG","BRI","AMT","PAR","TTG","TJT","TJL"]
			banjarbaru = ["LUL","LDU","BBR","BJB","MTP","MRB"]
			banjarmasin = ["KYG","ULI","BJM","KYI","ULN","GBT","GMB"]
			if sto in batulicin:
				datel = 'BATULICIN'
			elif sto in tanjung:
				datel = 'TANJUNG'
			elif sto in banjarbaru:
				datel = 'BANJARBARU'
			elif sto in banjarmasin:
				datel = 'BANJARMASIN'
			else:
				datel = ''
			forupdate = {
							'TGAL_SURVEY': tgl_survei,
							'LONGLAT': longlat,
							'LABEL': label_odp,
							'ONSITE': onsite,
							'ONDESK': ondesk,
							'KAP': kap,
							'AKTUAL_ODP': aktual_odp,
							'PORT_OLT': port_olt,
							'ALAMAT': alamat,
							'KENDALA': kendala,
							'USED': used,
							'OCCU': occu,
							'STO': sto,
							'ODC': odc,
							'DATEL': datel,
							'TANGGAL_UIM': tanggal_uim,
							'UIM': uim,
							'EKSEKUTOR': eksekutor,
							'last_modified': datetime.utcnow(),
						}
			forupdate.update(PORT)
			for each in forunset:
					mongo.db.dataodpmaster.update_one({ '_id':  odp_target },
										   {'$unset': {each:1}})

			mongo.db.dataodpmaster.update_one({ '_id':  odp_target },
								   {'$set': forupdate},upsert=True)
			if 'photo' in request.files:
				odp_name = odp_target.replace('/','-')
				name_fix = odp_name+'-'+time.strftime("%Y%m%d-%H%M%S")
				list_foto = os.listdir(os.getcwd()+'\\app\\static\\img')
				res_foto =  [i for i in list_foto if str(odp_name) in i]
				while len(res_foto) > 1:
					res_foto.sort()
					os.remove(os.getcwd()+'\\app\\static\\img\\'+res_foto[0]) 
					list_foto = os.listdir(os.getcwd()+'\\app\\static\\img')
					res_foto =  [i for i in list_foto if str(odp_name) in i]	
				filename = photos.save(request.files['photo'], name=name_fix+'.')
			if session['acc_type'] == 'admin':
				return redirect(url_for('odp_to_uim'))
			else:
				return redirect(url_for('list_odp'))
		return redirect(url_for('list_odp'))

@app.route('/data_rfs/update', methods=['POST'])
def update_rfs():
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		if request.method == 'POST':
			print 1
			print request.form['odp_target'].upper()
			print 2
			odp_target = request.form['odp_target'].upper()
			kendala = request.form['kendala'].upper()

			tanggal_uim = request.form['tanggal_uim']
			uim = request.form['uim'].upper()
			eksekutor = request.form['eksekutor'].upper()
		
			forupdate = {
							'KENDALA': kendala,
							'TANGGAL_UIM': tanggal_uim,
							'UIM': uim,
							'EKSEKUTOR': eksekutor,
							'last_modified': datetime.utcnow(),
						}
			print odp_target
			print forupdate
			mongo.db.dataodpmaster.update_one({ '_id':  odp_target },
								   {'$set': forupdate},upsert=True)
		
			return redirect(url_for('odp_to_uim'))
		return redirect(url_for('odp_to_uim'))


@app.route('/list_odp', methods=['GET', 'POST'])
# @login_required
def list_odp():
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		if request.method == 'POST':
			if request.form['btn'] == 'searchodp':
				id_db = request.form['odptosearch']
				tgal_db = request.form['tgltosearch']
				onsite_db = request.form['onsitetosearch']
				kap_db = request.form['kaptosearch']
				if kap_db == '':
					kap_db = ''
				else:
					kap_db = '^'+kap_db+'$'
				kendala_db = request.form['kendalatosearch']
				listodp = mongo.db.dataodpmaster.find({
				'_id': {'$regex': id_db, '$options': 'i'},
				'TGAL_SURVEY': {'$regex': tgal_db, '$options': 'i'},
				'$or': [{'ONSITE': {'$regex': onsite_db, '$options': 'i'}},{'ONDESK': {'$regex': onsite_db, '$options': 'i'}}],
				
				'KAP': {'$regex': kap_db, '$options': 'i'}, 
				'KENDALA': {'$regex': kendala_db, '$options': 'i'},
				}).sort([('last_modified',-1)]).limit(500)
				# for x in listodp:
				# 	print x['_id']
			elif request.form['btn'] == 'extract':
				listodp_x = [['TANGGAL SURVAI',
				'ODP TARGET',
				'AKTUAL ODP',
				'ALAMAT',
				'DATEL',
				'EKSEKUTOR',
				'KAP',
				'KENDALA',
				'LABEL',
				'LONGLAT',
				'ONSITE',
				'ONDESK',
				'PORT OLT',
				'STO',
				'TANGGAL UIM',
				'UIM',
				'OCCU',
				'ODC',
				'USED',
				'last_modified']]
				
				id_db = request.form['id_db']
				tgal_db = request.form['tgal_db']
				onsite_db = request.form['onsite_db']
				kap_db = request.form['kap_db']
				kendala_db = request.form['kendala_db']
				listodp = mongo.db.dataodpmaster.find({
				'_id': {'$regex': id_db, '$options': 'i'},
				'TGAL_SURVEY': {'$regex': tgal_db, '$options': 'i'},
				'ONSITE': {'$regex': onsite_db, '$options': 'i'},
				'KAP': {'$regex': kap_db, '$options': 'i'}, 
				'KENDALA': {'$regex': kendala_db, '$options': 'i'},
				}).sort([('last_modified',-1)])
				for x in listodp:
					listodp_y = []
					listodp_y.append(x.get('TGAL_SURVEY'))
					listodp_y.append(x.get('_id'))
					listodp_y.append(x.get('AKTUAL_ODP'))
					listodp_y.append(x.get('ALAMAT'))
					listodp_y.append(x.get('DATEL'))
					listodp_y.append(x.get('EKSEKUTOR'))
					listodp_y.append(x.get('KAP'))
					listodp_y.append(x.get('KENDALA'))
					listodp_y.append(x.get('LABEL'))
					listodp_y.append(x.get('LONGLAT'))
					listodp_y.append(x.get('ONSITE'))
					listodp_y.append(x.get('ONDESK'))
					listodp_y.append(x.get('PORT_OLT'))
					listodp_y.append(x.get('STO'))
					listodp_y.append(x.get('TANGGAL_UIM'))
					listodp_y.append(x.get('UIM'))
					listodp_y.append(x.get('OCCU'))
					listodp_y.append(x.get('ODC'))
					listodp_y.append(x.get('USED'))
					listodp_y.append(x.get('last_modified'))
					for y in x.values():
						if type(y) is dict:
							# for z in y.values():
							listodp_y.append(y.get('LABEL_PORT'))				
							listodp_y.append(y.get('STATUS'))				
							listodp_y.append(y.get('MODEM'))				
							listodp_y.append(y.get('NO_LAYANAN'))				
							listodp_y.append(y.get('LABEL_DROPCORE'))
					listodp_x.append(listodp_y)
				with open('tes.csv','wb') as f:
					writer = csv.writer(f)
					writer.writerows([[isunicode(co) for co in ro ] for ro in listodp_x])
				return send_file(os.getcwd()+'\\tes.csv',as_attachment=True)
		elif request.method == 'GET':
			id_db = ""
			tgal_db = ""
			onsite_db = ""
			kap_db = ""
			kendala_db = ""
			listodp = mongo.db.dataodpmaster.find().sort([('last_modified',-1)]).limit(20)
		lngth = mongo.db.dataodpmaster.find().count()
		lngthsearch = listodp.count()

		return render_template('list_odp.html', title='List ODP',lngthsearch=lngthsearch, listodp = listodp, lngth = lngth, id_db = id_db, tgal_db = tgal_db,
			onsite_db = onsite_db, kap_db = kap_db, kendala_db = kendala_db)

@app.route('/odp_to_uim', methods=['GET', 'POST'])
# @login_required
def odp_to_uim():
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		if request.method == 'POST':
			if request.form['btn'] == 'searchodp':
				id_db = request.form['odptosearch']
				tanggal_db = request.form['tgltosearch']
				tanggaluim_db = request.form['tgluimtosearch']
				uim_db = request.form['uimtosearch']
				occu_db = request.form['occutosearch']
				if uim_db == '':
					uim_db = ''
				else:
					uim_db = '^'+uim_db+'$'
				eksekutor_db = request.form['eksekutortosearch']
				if occu_db == "%" :
					listodp = mongo.db.dataodpmaster.find({
					'_id': {'$regex': id_db, '$options': 'i'},
					'TGAL_SURVEY': {'$regex': tanggal_db, '$options': 'i'},
					'TANGGAL_UIM': {'$regex': tanggaluim_db, '$options': 'i'},
					'UIM': {'$regex': uim_db, '$options': 'i'}, 
					'OCCU': occu_db, 
					'EKSEKUTOR': {'$regex': eksekutor_db, '$options': 'i'},
					}).sort([('last_modified',-1)]).limit(1000)
				else:
					listodp = mongo.db.dataodpmaster.find({
					'_id': {'$regex': id_db, '$options': 'i'},
					'TGAL_SURVEY': {'$regex': tanggal_db, '$options': 'i'},
					'TANGGAL_UIM': {'$regex': tanggaluim_db, '$options': 'i'},
					'UIM': {'$regex': uim_db, '$options': 'i'}, 
					'OCCU': {'$regex': occu_db, '$options': 'i'}, 
					'EKSEKUTOR': {'$regex': eksekutor_db, '$options': 'i'},
					}).sort([('last_modified',-1)]).limit(1000)

			elif request.form['btn'] == 'extract':
				listodp_x = [['TANGGAL SURVAI',
				'ODP TARGET',
				'AKTUAL ODP',
				'ALAMAT',
				'DATEL',
				'EKSEKUTOR',
				'KAP',
				'KENDALA',
				'LABEL',
				'LONGLAT',
				'ONSITE',
				'ONDESK',
				'PORT OLT',
				'STO',
				'TANGGAL UIM',
				'UIM',
				'OCCU',
				'ODC',
				'USED',
				'last_modified']]
				
				id_db = request.form['id_db']
				tanggal_db = request.form['tanggal_db']
				tanggaluim_db = request.form['tanggaluim_db']
				uim_db = request.form['uim_db']
				occu_db = request.form['occu_db']
				eksekutor_db = request.form['eksekutor_db']
				listodp = mongo.db.dataodpmaster.find({
				'_id': {'$regex': id_db, '$options': 'i'},
				'TGAL_SURVEY': {'$regex': tanggal_db, '$options': 'i'},
				'TANGGAL_UIM': {'$regex': tanggaluim_db, '$options': 'i'},
				'UIM': {'$regex': uim_db, '$options': 'i'}, 
				'OCCU': {'$regex': occu_db, '$options': 'i'}, 
				'EKSEKUTOR': {'$regex': eksekutor_db, '$options': 'i'},
				}).sort([('last_modified',-1)])
				for x in listodp:
					listodp_y = []
					listodp_y.append(x.get('TGAL_SURVEY'))
					listodp_y.append(x.get('_id'))
					listodp_y.append(x.get('AKTUAL_ODP'))
					listodp_y.append(x.get('ALAMAT'))
					listodp_y.append(x.get('DATEL'))
					listodp_y.append(x.get('EKSEKUTOR'))
					listodp_y.append(x.get('KAP'))
					listodp_y.append(x.get('KENDALA'))
					listodp_y.append(x.get('LABEL'))
					listodp_y.append(x.get('LONGLAT'))
					listodp_y.append(x.get('ONSITE'))
					listodp_y.append(x.get('ONDESK'))
					listodp_y.append(x.get('PORT_OLT'))
					listodp_y.append(x.get('STO'))
					listodp_y.append(x.get('TANGGAL_UIM'))
					listodp_y.append(x.get('UIM'))
					listodp_y.append(x.get('OCCU'))
					listodp_y.append(x.get('ODC'))
					listodp_y.append(x.get('USED'))
					listodp_y.append(x.get('last_modified'))
					for y in x.values():
						if type(y) is dict:
							# for z in y.values():
							listodp_y.append(y.get('LABEL_PORT'))				
							listodp_y.append(y.get('STATUS'))				
							listodp_y.append(y.get('MODEM'))				
							listodp_y.append(y.get('NO_LAYANAN'))				
							listodp_y.append(y.get('LABEL_DROPCORE'))
					listodp_x.append(listodp_y)
				with open('tes.csv','wb') as f:
					writer = csv.writer(f)
					writer.writerows([[isunicode(co) for co in ro ] for ro in listodp_x])
				return send_file(os.getcwd()+'\\tes.csv',as_attachment=True)
		elif request.method == 'GET':
			id_db = ""
			tanggal_db = ""
			tanggaluim_db = ""
			uim_db = ""
			occu_db = ""
			eksekutor_db = ""
			listodp = mongo.db.dataodpmaster.find().sort([('last_modified',-1)]).limit(500)
		lngth = mongo.db.dataodpmaster.find().count()
		lngthsearch = listodp.count()

		return render_template('odp_to_uim.html', title='List ODP',lngthsearch=lngthsearch, listodp = listodp, lngth = lngth, id_db = id_db, tanggal_db = tanggal_db, tanggaluim_db=tanggaluim_db, occu_db=occu_db,
			uim_db =uim_db, eksekutor_db = eksekutor_db)


@app.route('/delete_odp/<path:odp>', methods=['GET', 'POST'])
def delete_odp(odp):
	if not 'username' in session:
		return redirect(url_for('login'))
	else:
		# mongo.db.dataodpmaster.delete_one({ '_id':  odp })
		return redirect(url_for('list_odp'))
