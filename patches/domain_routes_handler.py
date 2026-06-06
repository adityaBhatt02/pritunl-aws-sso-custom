"""
domain_routes_handler.py
Add this file to: /usr/lib/pritunl/usr/lib/python3.9/site-packages/pritunl/handlers/
Then add this import to app.py:
    from pritunl.handlers import domain_routes_handler

API Endpoints:
    GET  /domain-routes         — list all domain routes
    POST /domain-routes         — add a domain route
    DELETE /domain-routes/<id>  — remove a domain route
"""

from pritunl import app
from pritunl import auth
from pritunl import utils
from pritunl import mongo

import flask
from bson import ObjectId
import datetime


def get_collection():
    from pymongo import MongoClient
    client = MongoClient('mongodb://localhost:27017/pritunl')
    return client['pritunl']['domain_routes']



@app.app.route('/domain-routes', methods=['GET'])
@auth.session_light_auth
def domain_routes_page():
    import os
    html_path = '/usr/share/pritunl/www/domain-routes.html'
    if os.path.exists(html_path):
        with open(html_path, 'r') as f:
            return flask.Response(f.read(), mimetype='text/html')
    return flask.abort(404)

@app.app.route('/domain-routes/list', methods=['GET'])
@auth.session_light_auth
def domain_routes_get():
    collection = get_collection()
    docs = list(collection.find({}))
    result = []
    for doc in docs:
        result.append({
            'id': str(doc['_id']),
            'domain': doc.get('domain', ''),
            'nat': doc.get('nat', True),
            'resolved_ips': doc.get('resolved_ips', []),
            'last_resolved': str(doc.get('last_resolved', '')),
            'error': doc.get('error'),
        })
    return utils.jsonify(result)


@app.app.route('/domain-routes', methods=['POST'])
@auth.session_light_auth
def domain_routes_post():
    domain = flask.request.json.get('domain', '').strip().lower()
    nat = flask.request.json.get('nat', True)

    if not domain:
        return utils.jsonify({'error': 'domain is required'}, 400)

    collection = get_collection()

    # Check duplicate
    existing = collection.find_one({'domain': domain})
    if existing:
        return utils.jsonify({'error': 'Domain already exists'}, 409)

    doc = {
        'domain': domain,
        'nat': nat,
        'resolved_ips': [],
        'last_resolved': None,
        'error': None,
        'created': datetime.datetime.utcnow(),
    }
    result = collection.insert_one(doc)

    # Trigger immediate resolution
    try:
        import socket
        results = socket.getaddrinfo(domain, None)
        ips = list(set([r[4][0] for r in results if ':' not in r[4][0]]))
        collection.update_one(
            {'_id': result.inserted_id},
            {'$set': {
                'resolved_ips': ips,
                'last_resolved': datetime.datetime.utcnow()
            }}
        )
    except Exception:
        pass

    return utils.jsonify({
        'id': str(result.inserted_id),
        'domain': domain,
        'nat': nat,
    })


@app.app.route('/domain-routes/<domain_id>', methods=['DELETE'])
@auth.session_light_auth
def domain_routes_delete(domain_id):
    collection = get_collection()
    collection.delete_one({'_id': ObjectId(domain_id)})
    return utils.jsonify({})
