function [unique_cves,unique_campaigns,unique_apts] = statistics_simulation(unique_cves,unique_campaigns,unique_apts,table_versions_campaign_product,campaigns_vulns_products_versions)
%compute statistics about cves, apts and campaigns analyzed by considering
%the products
    my_campaigns = unique(table_versions_campaign_product.('campaign'));
    my_cves = unique(table_versions_campaign_product.('cve'));
    
    %for the APTs is different, let's iterate over the ID campaign and get
    %the APT
    my_apts = [];
    for i=1:length(my_campaigns)
        tmp_apt = unique(campaigns_vulns_products_versions.('APT')(strcmp(campaigns_vulns_products_versions.('campaign'),my_campaigns(i))));
        my_apts = [my_apts; tmp_apt];
    end
    
    %drop duplicates
    
    my_campaigns = unique(my_campaigns);
    my_cves = unique(my_cves);
    my_apts = unique(my_apts);
    
    %move to output
    
    unique_cves = unique([unique_cves; my_cves]);
    unique_campaigns = unique([unique_campaigns; my_campaigns]);
    unique_apts = unique([unique_apts; my_apts]);
    
end

