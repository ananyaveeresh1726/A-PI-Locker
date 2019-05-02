
$.getCSS = function(path) {
    $('<link/>', {
       rel: 'stylesheet',
       type: 'text/css',
       href: path
    }).appendTo('head');
};

function Entry(type, name, value) {
    this.type = type;
    this.name = name;
    this.value = value;
    this.id = 'entry_value_' + this.type; 
    this.is_new = true;
}

Entry.prototype.Icon = function() {
    return 'keyboard-o';
}

Entry.prototype.Populate = function(o) {
    this.is_new = false;
    this.name = o.name;
    this.setValue(o.value);
}

Entry.prototype.setValue = function(v) {
    this.value = v;
}

Entry.prototype.getValue = function($elem) {
    this.value = $elem.val();
    return this.value;
}

Entry.prototype.Describe = function() {
    return JSON.stringify({
        type: this.type,
        name: this.name,
        new: this.is_new,
    });
}

Entry.prototype.formGroup = function(input) {
    return '<div class="form-group">' + 
             '<h5 class="editable label label-default entry-title label-' + this.type + '" id="editable_' + this.id + '">' + this.name + '</h5>' +
            '<div style="clear:both"></div>' +
             input +
            '</div>';
}

Entry.prototype.input = function(type, with_value) {
    return '<input ' + 
             'class="form-control" ' +
             'data-entry-type="' + this.type + '" ' +
             'type="' + type + '" ' + 
             'name="' + this.id + '" ' + 
             'id="' + this.id + '" ' +
             'value="' + ( with_value ? this.value : '' ) + '"' +
             ( type == 'file' ? 'multiple' : '' ) +
             '/>';
}

Entry.prototype.textarea = function(with_md, with_value) {
    return '<textarea ' + 
             'class="form-control" ' +
             ( with_md ? 'data-provide="markdown" ' : '' ) +
             'data-entry-type="' + this.type + '" ' +
             'name="' + this.name + '" ' + 
             'id="' + this.id + '" ' +
             '>' + ( with_value ? this.value : '' ) + '</textarea>';
}

Entry.prototype.li = function(html) {
    return '<li class="secret-entry-item" id="wrap_' + this.id + '">' + html + '</li>';
}

Entry.prototype.removeButton = function() {
    return '<a href="javascript:removeEntry(\'' + this.id + '\')"><i class="fa fa-trash" aria-hidden="true"></i></a>';
}

Entry.prototype.dragButton = function() {
    return '<a href="#" onclick="return false"><i class="fa fa-arrows" aria-hidden="true"></i></a>';
}

Entry.prototype.RenderToList = function(list) {
    var rendered = '<div class="entry-edit">' +
                     this.removeButton() +
                     this.dragButton() +
                   '</div>' +
                   this.Render(true);

    list.append( this.li( rendered ) );

    this.OnRendered();
}

Entry.prototype.Render = function(with_value){
    return "Unhandled entry type " + this.type;
}

Entry.prototype.OnRendered = function() { }
