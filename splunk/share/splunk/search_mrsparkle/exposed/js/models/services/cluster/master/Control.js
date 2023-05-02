define(
    [
        'jquery',
        'backbone',
        'models/StaticIdBase',
        'util/splunkd_utils'
    ],
    function($, Backbone, BaseModel, splunkDUtils){
        return BaseModel.extend({
            initialize: function() {
                BaseModel.prototype.initialize.apply(this, arguments);
            },
            sync: function(method, model, options) {
                var defaults = {
                    data: {
                        output_mode: 'json'
                    }
                };
                switch(method) {
                    case 'update':
                        defaults.processData = true;
                        defaults.type = 'POST';
                        defaults.url = splunkDUtils.fullpath(model.id);
                        $.extend(true, defaults, options);
                        break;
                    default:
                        throw new Error('invalid method: ' + method);
                }
                return Backbone.sync.call(this, method, model, defaults);
            }
        },
        {
            id: 'cluster/master/control/default/apply'
        });
    }
);
