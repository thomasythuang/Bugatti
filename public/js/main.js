$(document).ready(function() {

  $('#delete-location-button').click(function(){
    //I know this is really jank plz forgive me
    $('#location-form').attr('action', '/account/delete_location');
    $('#location-form').submit();
    $('#location-form').attr('action', '/account/select_location');
  });

});
