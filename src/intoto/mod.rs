use anyhow::{anyhow, Result};
use log::debug;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// Link import cgo function
#[link(name = "intoto")]
extern "C" {
    pub fn verifyGo(
        layoutPath: *const c_char, 
        pubKeyPaths: *const *const c_char, 
        pubKeyCountc: c_int,
        intermediatePathsc: *const *const c_char,
        intermediatePathCountc: c_int,
        linkDir: *const c_char, 
        lineNormalizationc: c_int, 
    ) -> *mut c_char;
}

pub fn verify(
    layout_path: String, 
    pub_key_paths: Vec<String>, 
    intermediate_paths: Vec<String>,
    link_dir: String,
    line_normalization: bool,
) -> Result<String> {

    // Convert Rust String to C char*
    let layout_path_c = layout_path.as_ptr() as *const c_char;

    // Convert Rust Vec<String> to C char**
    let pub_key_paths_cstr: Vec<_> = pub_key_paths.iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect();
    
    let mut pub_key_paths_cstr_pointer: Vec<_> = pub_key_paths_cstr.iter()
        .map(|arg| arg.as_ptr())
        .collect();
    
    pub_key_paths_cstr_pointer.push(std::ptr::null());
    
    let pub_key_paths_c: *const *const c_char = pub_key_paths_cstr_pointer.as_ptr();

    // Rust Vec len
    let pub_key_count_c = pub_key_paths.len() as c_int;

    // Convert Rust Vec<String> to C char**
    let intermediate_paths_cstr: Vec<_> = intermediate_paths.iter()
        .map(|arg| CString::new(arg.as_str()).unwrap())
        .collect();
    
    let mut intermediate_paths_cstr_pointer: Vec<_> = intermediate_paths_cstr.iter()
        .map(|arg| arg.as_ptr())
        .collect();
    
        intermediate_paths_cstr_pointer.push(std::ptr::null());
    
    let intermediate_paths_c: *const *const c_char = intermediate_paths_cstr_pointer.as_ptr();

    // Rust Vec len
    let intermediate_path_count_c = intermediate_paths.len() as c_int;

    // Convert Rust String to C char*
    let link_dir_c = link_dir.as_ptr() as *const c_char;

    // Convert Rust bool to C int
    let line_normalization_c = line_normalization as c_int;

    // Call the function exported by cgo and process the returned string
    let result_buf : *mut c_char = unsafe { verifyGo(
        layout_path_c,
        pub_key_paths_c,
        pub_key_count_c,
        intermediate_paths_c,
        intermediate_path_count_c,
        link_dir_c,
        line_normalization_c,
    )};

    let result_str: &CStr = unsafe {CStr::from_ptr(result_buf)};
    let res = result_str.to_str()?.to_string();
    debug!("In-toto verifyGo: {}", res);

    if res.starts_with("Error::") {
        return Err(anyhow!(res));
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::verify;

    #[test]
    fn good_provenance() {
        let layout_path = "tests/good_provenance/demo.layout".to_string();
        let pub_key_paths = vec!["tests/good_provenance/alice.pub".to_string()];
        let intermediate_paths = vec![];
        let link_dir = "tests/good_provenance".to_string();
        let line_normalization = true;
        let res = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        ).unwrap();
        assert_eq!(res, "".to_string());
    }

    #[test]
    fn bad_provenance() {
        let layout_path = "tests/bad_provenance/demo.layout".to_string();
        let pub_key_paths = vec!["tests/bad_provenance/alice.pub".to_string()];
        let intermediate_paths = vec![];
        let link_dir = "tests/bad_provenance".to_string();
        let line_normalization = true;
        assert!(verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        ).is_err());
    }
}