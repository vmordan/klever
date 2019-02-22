
function update_progress(mark_id, time_start) {
    if (!mark_id) {
        $.ajax({type: 'POST', url: '/marks/get_last_mark/', success:
            function (data) {
                if (data.error) {
                    err_notify(data.error);
                    return false;
                }
                mark_id = data['mark'];
            },
            async: false
        });
    }
    $.post(
        '/marks/get_progress/' + mark_id +'/', {},
        function (data) {
            if (data.error) {
                err_notify(data.error);
                return false;
            }
            if ($('#progress_bar').progress('get percent') < data['progress']) {
                $('#progress_bar').progress('set progress', data['progress']);
            }
            $('#progress_bar_mark_id').text(data['mark_id']);
            $('#progress_bar_mark_wall_time').text((performance.now() - time_start) / 1000);
            $('#progress_bar_mark_applied').text(data['applied']);
        }
    );
    return mark_id;
}