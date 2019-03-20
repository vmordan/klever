function toggle_by_id(identifier) {
    element = document.getElementById(identifier);
    if (!element) {
        return;
    }
    if (element.hidden) {
        element.hidden = false;
    } else {
        element.hidden = true;
    }
}

function apply_new_settings() {
    var elems = $('input:checkbox');
    var data = {};
    var comparison_attrs = [];
    var filtered_values = [];
    var same_transitions = [];
    var lost_transitions = [];
    var mea_config = {};
    for (var elem in elems) {
        var id = elems[elem].id;
        if (id && elems[elem].checked && id.startsWith('cs1__')) {
            comparison_attrs.push(id.replace(/^cs1__/,""));
        }
        if (id && !elems[elem].checked && id.startsWith('cs2__')) {
            filtered_values.push(id.replace(/^cs2__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs3__')) {
            same_transitions.push(id.replace(/^cs3__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs4__')) {
            lost_transitions.push(id.replace(/^cs4__/,""));
        }
        if (id && elems[elem].checked && id.startsWith('cs5__')) {
            mea_config['enable'] = true;
        }
    }
    elems = $('input:radio');
    var clustering_type = "";
    for (var elem in elems) {
        var id = elems[elem].id;
        if (id && elems[elem].checked && id.startsWith('cs5__show_')) {
            clustering_type = id.replace(/^cs5__show_/,"");
        }
    }
    mea_config['enable'] = $('#cs5__auto_cluster_traces').is(':checked');
    mea_config['clustering_type'] = clustering_type;
    mea_config['conversion'] = $('#cs5__conversion_function').val();
    mea_config['comparison'] = $('#cs5__comparison_function').val();
    mea_config['similarity'] = $('#cs5__similarity_threshold').val();

    data['comparison_attrs'] = comparison_attrs;
    data['filtered_values'] = filtered_values;
    data['same_transitions'] = same_transitions;
    data['lost_transitions'] = lost_transitions;
    data['mea_config'] = mea_config;
    $('#dimmer_of_page').addClass('active');
    window.location.href = get_url_with_get_parameter(window.location.href, 'data', JSON.stringify(data));
}

$(document).ready(function () {
    $('div[id^="acc_row_attrs_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_attrs_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_et_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_et_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_res_"]').children('div[class^="title"]').click(function (data) {
        $('div[id^="acc_row_res_"]').accordion('toggle', 0);
    });
    $('div[id^="acc_row_"]').accordion({
        selector: {
          trigger: null
        }
    });

    $('#apply_new_settings').click(function () {
        $(this).addClass('disabled');
        apply_new_settings();
    });
    $('#cancel_settings').click(function () {
        window.location.replace('/reports/comparison/' + $('#job_id_1').val() + "/" + $('#job_id_2').val());
    });
     $('#exchange').click(function () {
        var settings = window.location.search;
        window.location.replace('/reports/comparison/' + $('#job_id_2').val() + "/" + $('#job_id_1').val() + settings);
    });

});