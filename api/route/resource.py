from http import HTTPStatus
from flask import Blueprint
from flasgger import swag_from
from api.schema.resource import ResourceSchema
from api.schema.exception import ExceptionSchema
from api.model.resource import ResourceModel
from api.model.exception import ExceptionModel
from services.resource_service import ResourceService


resource_api = Blueprint('resources', __name__)


@resource_api.route('/<provider>')
@swag_from({
    'responses': {
        HTTPStatus.OK.value: {
            'description': 'Fetch cloud resources from service account file',
            'schema': ResourceSchema
        }
    }
})
def fetchResources(provider):
    """
    Fetch resources and metadata using cloud API's in real time.
    ---
    parameters:
      - name: provider
        in: path
        type: string
        enum: ['gcp', 'aws', 'azure']
        required: true
        default: gcp
    """
    try:
        resource_service_obj = ResourceService(provider)
        pretty_resources, _ = resource_service_obj.get_resource()
    except Exception as ex:
        exception = {
            "message": ex,
            "status": 400
        }
        return ExceptionSchema().dump(ExceptionModel(exception)), 400
    # print(pretty_resources)
    return ResourceSchema().dump(ResourceModel(pretty_resources)), 200
