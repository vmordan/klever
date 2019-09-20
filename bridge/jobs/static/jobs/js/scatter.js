/*
 * Klever-CV is a web-interface for continuous verification results visualization.
 *
 * Copyright (c) 2018-2019 ISP RAS (http://www.ispras.ru)
 * Ivannikov Institute for System Programming of the Russian Academy of Sciences
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * ee the License for the specific language governing permissions and
 * limitations under the License.
 */

google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(draw_scatter);

function get_number_of_digits(number) {
    return number.toString().length;
}

function get_log_ticks(min_value, max_value) {
    var ticks = [];
    var counter;
    if (min_value < 1 && min_value > 0) {
        counter = 1;
        while (counter > min_value) {
            counter /= 10.0;
            ticks.push(counter);
        }
    }
    counter = Math.pow(10, get_number_of_digits(Math.round(min_value)) - 1);
    ticks.push(counter);
    while (counter < max_value) {
        counter *= 10;
        ticks.push(counter);
    }
    return ticks;
}

function draw_scatter(res_name=null) {
    if (!res_name) {
        res_name = $('#compared_resources').children().first().val();
    }
    var data = new google.visualization.DataTable();
    var job1_id = $('.job1').attr("id");
    var job2_id = $('.job2').attr("id");
    var job1_name = $('.job1').text();
    var job2_name = $('.job2').text();
    data.addColumn('number', job1_name);
    data.addColumn('number', job2_name);
    data.addColumn({type:'string', role:'tooltip', 'p': {'html': true}});
    data.addColumn('number', "Aux line");
    var row_data = [];
    var max_value = 0;
    var min_value = Number.MAX_SAFE_INTEGER;
    var selected_table = $('table[id="scatter-' + res_name + '"]');
    selected_table.find('tr').each(function () {
        var children = $(this).children();
        var common_attr = children[0].innerHTML;
        var report_1 = children[1].innerHTML;
        var report_2 = children[2].innerHTML;
        var value_1 = parseFloat(children[3].innerHTML.replace(/,/, '.'));
        var value_2 = parseFloat(children[4].innerHTML.replace(/,/, '.'));
        var tooltip = "<h4 class='ui header center aligned'>" + res_name + "</h4><br><table><tr>" +
            "<td><a class='blue-link' href=/jobs/" + job1_id + ">" + job1_name + "</a>:</td>" +
            "<td><a class='blue-link' href=/reports/component/" + report_1 + ">" + value_1 + "</a></td></tr>" +
            "<tr><td><a class='blue-link' href=/jobs/" + job2_id + ">" + job2_name + "</a>:</td>" +
            "<td><a class='blue-link' href=/reports/component/" + report_2 + ">" + value_2 + "</a></td></tr></table>";
        row_data.push([value_1, value_2, tooltip, null]);

        if (value_1 > max_value) {
            max_value = value_1;
        }
        if (value_1 < min_value) {
            min_value = value_1;
        }
        if (value_2 > max_value) {
            max_value = value_2;
        }
        if (value_2 < min_value) {
            min_value = value_2;
        }
    });
    var ticks = get_log_ticks(min_value, max_value);
    var max_val = Math.max(ticks[ticks.length - 1], ticks[ticks.length - 1])
    row_data.push([0, null, null, 0]);
    row_data.push([max_val, null, null, max_val]);
    data.addRows(row_data);

    var options = {
        hAxis: {
            title: job1_name,
            logScale: true,
            ticks: ticks,
            format: 'decimal'
        },
        vAxis: {
            title: job2_name,
            logScale: true,
            ticks: ticks,
            format: 'decimal'
        },
        series: {
            1: {
                lineWidth: 1.0,
                pointSize: 0,
                curveType: 'function',
                color: 'grey',
                opacity: 1.0,
                visibleInLegend: false,
                tooltip : false,
                type: 'line'
            }
        },
        seriesType: 'scatter',
        colors: ["red"],
        height: 800,
        width: 800,
        pointSize: 3,
        legend: { position: 'none'},
        tooltip: {isHtml: true, trigger: "selection"}
    };

    var chart = new google.visualization.ComboChart(document.getElementById('chart'));
    chart.draw(data, options);
}

$(document).ready(function () {
    $('#apply_attributes').click(function () {
        $(this).addClass('disabled');
        var elems = $('input:checkbox');
        var cur_url = window.location.href;
        var args = {};


        for (var elem in elems) {
            if (elems[elem].id && !elems[elem].checked && elems[elem].id.startsWith('compare_')) {
                var attr = elems[elem].id.replace('compare_', 'ignore_');
                args[attr] = elems[elem].value;
            }
        }
        $(this).removeClass('disabled');
        window.location.href = get_url_with_get_parameter(window.location.href, 'args', JSON.stringify(args));
    });
    $('#exchange').click(function () {
        var settings = window.location.search;
        window.location.href = '/jobs/scatter/' + $('.job2').attr("id") + "/" + $('.job1').attr("id") + settings;
    });
});