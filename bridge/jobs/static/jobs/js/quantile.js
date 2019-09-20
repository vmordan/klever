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
google.charts.setOnLoadCallback(draw_quantile);

function get_number_of_digits(number) {
    return number.toString().length;
}

function draw_quantile(y_axis=null) {
    if (!y_axis) {
        y_axis = $('#compared_resources').children().first().val();
    }
    var resources = [];
    var x_axis = $('#trans__number_of_tasks').text();
    var trans_report = $('#trans__report').text();
    var trans_job = $('#trans__job').text();
    var data = new google.visualization.DataTable();
    data.addColumn('number', x_axis);
    var job_ids = {};
    $('.job_id').each(function () {
        var job_name = $(this).text();
        var job_id = $(this).attr("id");
        job_ids[job_id] = job_name;
    });
    var counter_job_id = 1;
    row_data = [];
    var max_value = 0;
    var min_value = Number.MAX_SAFE_INTEGER;
    $('table[id^="table-"]').each(function () {
        var job_id = $(this).attr('id').replace('table-', '');
        var job_name = job_ids[job_id];
        var counter = 0;
        data.addColumn('number', job_name);
        data.addColumn({type:'string', role:'tooltip', 'p': {'html': true}});
        $(this).find('tr[class="resources ' + y_axis + '"]').each(function () {
            var children = $(this).children();
            var report_id = $(this).children()[2].innerHTML;
            var value = parseFloat(children[1].innerHTML.replace(/,/, '.'));
            var tooltip = x_axis + ": <b>" + (counter + 1) + "</b><br>" + y_axis + ": <b>" + value + "</b><br>" +
                trans_report + ": " + "<a class='blue-link' href=/reports/component/" + report_id + ">" +
                children[0].innerHTML + "</a><br>" + trans_job + ": <a class='blue-link' href=/jobs/" + job_id + ">" +
                job_name + "</a>";
            if (row_data.length <= counter) {
                row_data[counter] = [counter + 1];
                for(var i = 0; i < Object.keys(job_ids).length; i++) {
                    row_data[counter].push(null);
                    row_data[counter].push(null);
                }
            }

            row_data[counter][counter_job_id] = value;
            if (value > max_value) {
                max_value = value;
            }
            if (value < min_value) {
                min_value = value;
            }
            row_data[counter][counter_job_id + 1] = tooltip;
            counter++;
        });
        counter_job_id += 2;
    });
    data.addRows(row_data);
    var ticks = [];
    if (min_value < 1 && min_value > 0) {
        counter = 1;
        while (counter > min_value) {
            counter /= 10.0;
            ticks.push(counter);
        }
    }
    var counter = Math.pow(10, get_number_of_digits(Math.round(min_value)) - 1);
    ticks.push(counter);
    while (counter < max_value) {
        counter *= 10;
        ticks.push(counter);
    }
    var options = {
        hAxis: {
            title: $('#trans__quantile_x_axis').text(),
            gridlines: { count: -1 },
            minorGridlines: { count: -1 }
        },
        vAxis: {
            title: y_axis,
            logScale: true,
            gridlines: { count: -1 },
            minorGridlines: { count: -1 },
            ticks: ticks,
            format: 'decimal'
        },
        colors: ["red", "blue", "green", "olive", "purple", "aqua", "black", "orange", "gray"],
        height: 600,
        legend: { position: 'top', maxLines: 4},
        tooltip: {isHtml: true, trigger: "selection"},
    };

    var chart = new google.visualization.LineChart(document.getElementById('chart'));
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
});