from flask import Flask, render_template, request
from pymongo import MongoClient

app = Flask(__name__)
client = MongoClient('mongodb://localhost:27017/')
db = client['Mufeeth']
collection = db['Vulnerabilities']
collection_new = client['Mufeeth']['Vulnerabilities']

DEFAULT_PER_PAGE = 10

@app.route('/cves/list', methods=['GET', 'POST'])
def index():
    results_per_page = int(request.args.get('resultsPerPage', 10))
    page_number = int(request.args.get('page', 1))
    sort_order = int(request.args.get('sort_order', 1))  
    
    skip = (page_number - 1) * results_per_page
    total_records = collection.count_documents({})
    total_pages = (total_records + results_per_page - 1) // results_per_page
    data = collection.find({}, {'cve.id': 1, 'cve.sourceIdentifier': 1, 'cve.published': 1, 'cve.lastModified': 1,
                                 'cve.vulnStatus': 1}) \
                     .skip(skip) \
                     .limit(results_per_page) \
                     .sort('cve.id', sort_order)
    
    return render_template('index.html', data=data, results_per_page=results_per_page, page_number=page_number,
                           total_pages=total_pages, total_records=total_records, sort_order=sort_order)

@app.route('/details/<cve_id>')
def cve_detail(cve_id):
    cve_details = collection_new.find_one({'cve.id': cve_id})

    if not cve_details:
        return render_template('error.html', message=f'CVE {cve_id} not found')

    return render_template('details.html', cve_details=cve_details)

if __name__ == '__main__':
    app.run(debug=True)
