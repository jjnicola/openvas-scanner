use nvtcache::dberror::Result;
use nvtcache::nvt::{Category, Nvt, NvtRef};

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_nvt() {
        let mut nvt;
        let res = Nvt::new();

        match res {
            Ok(ok) => nvt = ok,
            Err(_) => panic!("No Nvt"),
        }
        //Add first tag
        nvt.add_tag("Tag Name".to_string(), "Tag Value".to_string());
        let tag = nvt.get_tag();
        assert_eq!(tag, "Tag Name=Tag Value");

        //Add second tag
        nvt.add_tag("Tag Name1".to_string(), "Tag Value1".to_string());
        let tag = nvt.get_tag();
        assert_eq!(tag, "Tag Name=Tag Value|Tag Name1=Tag Value1");
    }

    #[test]
    fn test_bid_refs() -> Result<()> {
        let mut nvt = Nvt::new()?;
        let bid_refs1 = NvtRef::new(
            "bid".to_owned(),
            "BID_ID1".to_owned(),
            "BID-text".to_owned(),
        )?;
        let bid_refs2 = NvtRef::new(
            "bid".to_owned(),
            "BID_ID2".to_owned(),
            "BID-text".to_owned(),
        )?;

        nvt.add_ref(bid_refs1);
        nvt.add_ref(bid_refs2);
        let bid;
        (_, bid, _) = nvt.get_refs();

        assert_eq!(bid, "BID_ID1, BID_ID2");

        Ok(())
    }
    #[test]
    fn test_cve_refs() -> Result<()> {
        let mut nvt = Nvt::new()?;
        let cve_refs1 = NvtRef::new(
            "cve".to_owned(),
            "cve_ID1".to_owned(),
            "CVE-text".to_owned(),
        )?;
        let cve_refs2 = NvtRef::new(
            "cve".to_owned(),
            "cve_ID1".to_owned(),
            "CVE-text".to_owned(),
        )?;
        nvt.add_ref(cve_refs1);
        nvt.add_ref(cve_refs2);
        let cve;
        (cve, _, _) = nvt.get_refs();
        assert_eq!(cve, "cve_ID1, cve_ID1");

        Ok(())
    }
    #[test]
    fn test_xrefs() -> Result<()> {
        let mut nvt = Nvt::new()?;
        let xrefs1 = NvtRef::new(
            "URL".to_owned(),
            "http://greenbone.net".to_owned(),
            "some text".to_owned(),
        )?;
        let xrefs2 = NvtRef::new(
            "URL".to_owned(),
            "http://openvas.net".to_owned(),
            "some text".to_owned(),
        )?;

        nvt.add_ref(xrefs1);
        nvt.add_ref(xrefs2);
        let xrefs;
        (_, _, xrefs) = nvt.get_refs();
        assert_eq!(xrefs, "URL:http://greenbone.net, URL:http://openvas.net");

        Ok(())
    }

    #[test]
    fn test_category_from_trait() {
        let cat = Category::ActEnd;

        assert_eq!(cat.to_string(), "10");
    }
}