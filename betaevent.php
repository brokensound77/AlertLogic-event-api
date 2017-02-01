<html>
<head>
    <title>AL Rollup</title>
    <meta name="viewport" content="width=device-width">
    <meta charset="utf-8">
    <script src="https://use.fontawesome.com/037d7941f1.js"></script>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/css/bootstrap.min.css" integrity="sha384-rwoIResjU2yc3z8GV/NPeZWAv56rSmLldC3R/AZzGRnGxQQKnKkoFVhFQhNUwEyJ" crossorigin="anonymous">
    <script src="https://code.jquery.com/jquery-3.1.1.slim.min.js" integrity="sha384-A7FZj7v+d/sdmMqp/nOQwliLvUsJfDHW+k9Omg/a/EheAdgtzNs3hpfag6Ed950n" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/tether/1.4.0/js/tether.min.js" integrity="sha384-DztdAPBWPRXSA/3eYEEUWrWCy7G5KFbe8fFjk5JAIxUYHKkDx6Qin1DkWx51bBrb" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-alpha.6/js/bootstrap.min.js" integrity="sha384-vBWWzlZJ8ea9aCX4pEW3rVHjgjt7zpkNpZk+02D9phzyeVkE+jo0ieGizqPLForn" crossorigin="anonymous"></script>
    <style>
        body{
            padding:1em;
        }
        pre {
            tab-width: 4;
            display: block;
            padding: 1em;
            margin: 0 0 3em;
            font-size: 1em;
            line-height: 1.42857143;
            color: #333;
            word-break: break-all;
            word-wrap: break-word;
            border: 1px solid #000;
            border-radius: 4px;
            white-space: pre-wrap;
        }
        .card-header a {
            display: inline-block;
            width: 100%;
        }
        .mini-card-header {
            font-size: 0.6em;
            text-decoration: none;
            float: right;
            color: black;
            font-weight: 100;
            padding-top: 0.4em;
        }
    </style>

    <script>
        <?php
        $cid = $_GET["cid"];
        $iid = $_GET["iid"];

        putenv("/opt/csoc/al_events/AlertLogicTools_dev/AlertLogic-event-api/src");
        $code = "python /opt/csoc/al_events/AlertLogicTools_dev/AlertLogic-event-api/main.py -f /opt/csoc/al_events/AlertLogicTools_dev/AlertLogic-event-api/config.cfg -c ".escapeshellarg($cid)." -i ".escapeshellarg($iid);
        console.log($code);
        $json_event_string = exec( $code,$output, $return);
        //}
        ?>
        $(document).ready(function(){
            $("a[data-toggle='collapse']:even").click();
            $(".card-block pre:odd").css("background-color","#C8C8C8 ");

        });
    </script>
</head>
<body>
<?php
if ($return == 0){
    $event_json = json_decode($json_event_string,true);
    //Summary Details First
    $event_ids = [];
    echo '<h3>Summary</h3><pre class="section">';
        foreach ($event_json["events_summary"]["summary_breakdown"] as $signatures => $signature){
            echo $signatures.":";
            foreach ($signature as $hosts => $host){
                echo "<br>\t".$hosts.':';
                foreach ($host as $codes => $code){
                    echo "<br>\t\t".$codes.':';
                    foreach ($code as $event){
                        echo "<br>\t\t\t".$event;
                    }
                }
            }
        }
    echo '</pre>';
    foreach( $event_json["events_summary"]["event_summary"]["unique_signatures"] as $signature){
            array_push($event_ids,$signature[0]);
    }
    echo '<h3>Signature Details</h3><pre class="section">';
    echo '<div class="panel-group" id="accordion-sig" role="tablist" aria-multiselectable="true">';
    echo '<div class="card">';
    echo '<div class="card-header" role="tab" id="heading-sig">';
    echo '<h5 class="mb-0">';
    echo '<a data-toggle="collapse" data-parent="#accordion-sig" href="#collapse-sig" aria-expanded="true" aria-controls="collapse-sig">Results (Click to Hide)';
    echo '<span class="mini-card-header">(click to toggle collapse)</span>';
    echo '</a>';
    echo '</h5>';
    echo '</div>';
    echo '<div class="collapse in" role="tabpanel" aria-labelledby="heading-sig" id="collapse-sig">';
    echo '<div class="card-block">';
    foreach ($event_ids as $event){
        echo "<pre>";
        echo 'Name: '. $event_json["events"][$event]["event_details"]["signature_name"]."<br>";
        echo "\tID: ".$event_json['events'][$event]['signature_details']['sig_id']."<br>";
        echo "\tRule: ".$event_json['events'][$event]['signature_details']['sig_rule']."<br>";
        echo "</pre>";
    }
    echo '</pre>';

    echo '</a>';
    echo '</h5>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';

    echo "<h3>CMS</h3><pre class='section'>";
    echo '<div class="panel-group" id="accordion-cms" role="tablist" aria-multiselectable="true">';
    echo '<div class="card">';
    echo '<div class="card-header" role="tab" id="heading-cms">';
    echo '<h5 class="mb-0">';
    echo '<a data-toggle="collapse" data-parent="#accordion-cms" href="#collapse-cms" aria-expanded="true" aria-controls="collapse-cms">(Click to Hide)';
    echo '<span class="mini-card-header">(click to toggle collapse)</span>';
    echo '</a>';
    echo '</h5>';
    echo '</div>';
    echo '<div class="collapse in" role="tabpanel" aria-labelledby="heading-cms" id="collapse-cms">';
    echo '<div class="card-block">';

    foreach($event_json["cms"] as $site){
        echo "<pre>";
        echo $site;
        echo "</pre>";
    }
    echo '</pre>';
    echo '</a>';
    echo '</h5>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';

    //Full Events
    echo "<h3>Full Events</h3><pre class='section'>";
    foreach($event_json["events"] as $event => $v){
        echo '<div class="panel-group" id="accordion'.$event.'" role="tablist" aria-multiselectable="true">';
        echo '<div class="card">';
        echo '<div class="card-header" role="tab" id="heading-'.$event.'">';
        echo '<h5 class="mb-0">';
        echo '<a data-toggle="collapse" data-parent="#accordion'.$event.'" href="#collapse'.$event.'" aria-expanded="true" aria-controls="collapse'.$event.'">Event '.$event;
        echo '<span class="mini-card-header">(click to toggle collapse)</span>';
        echo '</a>';
        echo '</h5>';
        echo '</div>';
        echo '<div class="collapse in" role="tabpanel" aria-labelledby="heading-'.$event.'" id="collapse'.$event.'">';
        echo '<div class="card-block">';
        echo '<a href="'.$v["event_url"].'">'.'Link to Event</a>'."<br><br>";
        echo "Details:<br>";
        echo '<pre>';
        foreach($v["event_details"] as $key => $value){
            echo "\t".$key.": ".$value;
            echo "<br>";
        }
        echo '</pre>';
        echo "<br>";
        echo "Packet Details:<br>";
        echo '<pre>';
        foreach($v["event_payload"]["packet_details"] as $key2 => $value2){
            echo "\t".$key2.":"."<br>";
            foreach($value2 as $key3 => $value3){
                echo "\t\t".$key3.": ".$value3;
                echo "<br>";
            }
        }
        echo '</pre>';
        echo "Decompressed:<br>";
        echo '<pre>';
        echo htmlspecialchars($v["event_payload"]["Decompressed Data"]);
        echo '</pre>';
        echo "Full Payload:<br>";
        echo '<pre>';
        echo htmlspecialchars($v["event_payload"]["full_payload"]);
        echo "</pre>";
        echo '<div class="card-header" role="tab" id="collapse-heading-'.$event.'">';
        echo '<h5 class="mb-0">';
        echo '<a class="bottom-collapse" data-toggle="collapse" data-parent="#accordion'.$event.'" href="#collapse'.$event.'" aria-expanded="true" aria-controls="collapse'.$event.'">Collapse Event Above';
        echo '</a>';
        echo '</h5>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
    }
    echo '</pre>';
    // everything else
    /*
    foreach($ptest as $key => $value)
    {
        if($key != "summary" && $key != "details"){
            echo '<h3>' . htmlspecialchars($key) . '</h3><pre class="section">';
            if($key != "events"){
                echo $value;
            }
            else{
                // process and make subsections
                //echo htmlspecialchars(var_dump($value));
            }
            echo '</pre>';
        }
    }
    */
    //echo htmlspecialchars($test["details"]);
    //echo htmlspecialchars($test["events"]);
    //echo htmlentities($line);
} else {
    echo "Unable to process event";
}
?>
</body>
</html>
