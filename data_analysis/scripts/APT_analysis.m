%this script computes statistics on the APT campaigns and vulnerabilities
clear all
close all
%load data about APTs
folder_data = '../';
campaigns_vulns_vector_product_version_os = readtable(strcat(folder_data,'campaigns_vulnerability_vector_product_version_os.csv'),'ReadVariableNames',true,'Delimiter',',');
campaigns_vulns_vector_product_version_os.('campaign') = string(campaigns_vulns_vector_product_version_os.('campaign'));
campaigns_vulns_vector_product_version_os.('exploited_time') = datetime(campaigns_vulns_vector_product_version_os.('exploited_time'),'InputFormat','yyyy-MM-dd');
campaigns_vulns_vector_product_version_os.('reserved_time') = datetime(campaigns_vulns_vector_product_version_os.('reserved_time'),'InputFormat','yyyy-MM-dd');
campaigns_vulns_vector_product_version_os.('published_time') = datetime(campaigns_vulns_vector_product_version_os.('published_time'),'InputFormat','yyyy-MM-dd');

%load data about software releases
products_paper = ["jre","air","acrobat_reader","flash_player","office"];

folder_versions = '../';
air_versions_file = 'air_versions_v2.csv';
reader_versions_file = 'reader_versions_v2.csv';
jre_versions_file = 'jre_versions_v2.csv';
flash_versions_file = 'flash_versions_v2.csv';
office2016_versions_file = 'office2016_versions_v2.csv';

air_versions = readtable(strcat(folder_versions,air_versions_file),'ReadVariableNames',true,'Delimiter',',','Format','%s%s%s%s%s');
reader_versions = readtable(strcat(folder_versions,reader_versions_file),'ReadVariableNames',true,'Delimiter',',','Format','%s%s%s%s%s');
jre_versions = readtable(strcat(folder_versions,jre_versions_file),'ReadVariableNames',true,'Delimiter',',','Format','%s%s%s%s%s');
flash_versions = readtable(strcat(folder_versions,flash_versions_file),'ReadVariableNames',true,'Delimiter',',','Format','%s%s%s%s%s');
office2016_versions = readtable(strcat(folder_versions,office2016_versions_file),'ReadVariableNames',true,'Delimiter',',','Format','%s%s%s%s%s');

%mapping vendor advisory to CVE
air_advisory = 'air_advisory.xlsx';
flash_advisory = 'flash_advisory.xlsx';
acrobat_advisory = 'acrobat_advisory.xlsx';
jdk_advisory = 'jdk_advisory.xlsx';
office_advisory = 'office2016_advisory.xlsx';

air_advisory_tab = readtable(strcat(folder_versions,air_advisory),'ReadVariableNames',true);
flash_advisory_tab = readtable(strcat(folder_versions,flash_advisory),'ReadVariableNames',true);
acrobat_advisory_tab = readtable(strcat(folder_versions,acrobat_advisory),'ReadVariableNames',true);
jdk_advisory_tab = readtable(strcat(folder_versions,jdk_advisory),'ReadVariableNames',true);
office_advisory_tab = readtable(strcat(folder_versions,office_advisory),'ReadVariableNames',true);
office_advisory_tab.('advisory')= cellstr(string(office_advisory_tab.('advisory')));

products_advisories = [air_advisory_tab;flash_advisory_tab;acrobat_advisory_tab;jdk_advisory_tab;office_advisory_tab];

%load all the CVE associated to the products of interest 
vuln_v2 = 'Vulnerabilities_v2.csv';
%this contains all CVEs affecting the 5 products of interest
all_vulns_tab = readtable(strcat(folder_data,vuln_v2),'ReadVariableNames',true);
all_vulns_tab.('reservedDate') = datetime(all_vulns_tab.('reservedDate'),'InputFormat','yyyy-MM');
all_vulns_tab.('publishedDate') = datetime(all_vulns_tab.('publishedDate'),'InputFormat','yyyy-MM');

%clean the office2016 file
office2016_versions = unique(office2016_versions);

%join together all the versions product to iterate over all automatically
%(for office let's ignore the last column that matches the CVE associated)
products_versions = [air_versions;reader_versions;jre_versions;flash_versions;office2016_versions];

%join together version and update to compare quickly later
products_versions = table(products_versions.('product'),strcat(products_versions.('version'),'-',products_versions.('update')),products_versions.('release_date'),products_versions.('advisory'),'VariableNames',{'product','version','release_date','advisory'});

%%
%create a table with compacted info about campaigns of APTs with related
%product affected
campaigns_products = unique(table(campaigns_vulns_vector_product_version_os.('APT'),campaigns_vulns_vector_product_version_os.('campaign'),campaigns_vulns_vector_product_version_os.('exploited_time'),campaigns_vulns_vector_product_version_os.('product')));
campaigns_products.Properties.VariableNames = {'APT','campaign','exploited_time','product'};
%drop line with empty products
campaigns_products(ismissing(campaigns_products.('product')),:)=[];

%get the list of campaigns that exploit a CVE
idx_missing_CVE = ismissing(campaigns_vulns_vector_product_version_os.('vulnerability'));
tot_campaigns = unique(campaigns_vulns_vector_product_version_os.('campaign'));
campaigns_no_CVE = unique(campaigns_vulns_vector_product_version_os.('campaign')(idx_missing_CVE));
campaigns_CVE = setdiff(tot_campaigns,campaigns_no_CVE);
%count number of campaigns with at least one vulnerability exploited
n_campaigns_CVE = length(campaigns_CVE);

%get the list of APTs
apts = unique(campaigns_vulns_vector_product_version_os.('APT'));

%get first 10 products with highest number of campaigns
[a,b] = histcounts(categorical(campaigns_products.('product')));
table_products = table(a',b',(a'.*100)/size(campaigns_CVE,1),'VariableNames',{'n_campaigns','product','percentage_campaign'});
%order by number of campaign
table_products = sortrows(table_products,'n_campaigns','descend');
%get the first 10 products
table_products(1:10,:)

%create table with only APT and associated CVE
apts_vulnerabilities = table(campaigns_vulns_vector_product_version_os.('APT')(~idx_missing_CVE),campaigns_vulns_vector_product_version_os.('campaign')(~idx_missing_CVE),campaigns_vulns_vector_product_version_os.('vulnerability')(~idx_missing_CVE),campaigns_vulns_vector_product_version_os.('reserved_time')(~idx_missing_CVE),campaigns_vulns_vector_product_version_os.('published_time')(~idx_missing_CVE),campaigns_vulns_vector_product_version_os.('exploited_time')(~idx_missing_CVE));
apts_vulnerabilities.Properties.VariableNames = {'APT','campaign','CVE','reserved_time','published_time','exploited_time'};
%reduce lines eliminating duplicates
apts_vulnerabilities = unique(apts_vulnerabilities);
%sort by exploited date to then take only the first occurence of each CVE
apts_vulnerabilities = sortrows(apts_vulnerabilities,'exploited_time');
CVEs = unique(apts_vulnerabilities.('CVE'));
for i=1:length(CVEs)
    apts_tmp = apts_vulnerabilities(strcmp(apts_vulnerabilities.('CVE'),CVEs(i)),:);
    %already sorted so just extract the first one
    apts_tmp = apts_tmp(1,:);
    if i==1
        %create the table
        first_occurence_vulnerability = apts_tmp;
    else
        first_occurence_vulnerability = [first_occurence_vulnerability; apts_tmp];
    end
end

top_cves = table();
for i=1:length(CVEs)
   my_cve = CVEs(i);
   n_camps = length(unique(campaigns_vulns_vector_product_version_os.('campaign')(strcmp(campaigns_vulns_vector_product_version_os.('vulnerability'),my_cve))));
   top_cves = [top_cves;table(my_cve,n_camps,'VariableNames',{'vulnerability','n_campaigns'})];
end
top_cves = sortrows(top_cves,'n_campaigns','descend');

% clear stuff
clear a b 

%% VULNERABILITY SECTION

%### Exploit Age ###
%columns containing dates are already in datetime format
%compute difference between published date (NVD) and *first time* observed exploited date
%this is in days, convert to month
delta_time_NVD = datenum(first_occurence_vulnerability.('exploited_time')) - datenum(first_occurence_vulnerability.('published_time'));
delta_time_NVD_months = round(delta_time_NVD/30);
fprintf("Mean (months):%d\nMode (months):%d\nMedian (months):%d\n",mean(delta_time_NVD_months),mode(delta_time_NVD_months),median(delta_time_NVD_months));


%evolution on 0-days usage over the years
%get years when a 0-day was exploited
idx_exploited_before_publication = apts_vulnerabilities.('exploited_time')<apts_vulnerabilities.('published_time');
tmp = table(apts_vulnerabilities.('CVE')(idx_exploited_before_publication),apts_vulnerabilities.('exploited_time')(idx_exploited_before_publication));
final_tmp = table();
cves_tmp = unique(tmp.('Var1'));
%drop 0-days that are exploited multiple time
for i=1:length(cves_tmp)
    %get the first one because it is already sorted
    index = find(contains(tmp.('Var1'),cves_tmp(i)),1,'first');
    final_tmp = [final_tmp; tmp(index,:)];
end

final_tmp.('Var2') = year(final_tmp.('Var2'));
years_0day = final_tmp.('Var2');
%get the value for each
values_per_year = histcounts(categorical(years_0day));
%it could be we do not have any 0-day in a year but it will not be plotted
%therefore fix it
interval_time = [min(years_0day):1:max(years_0day)];
values_interval = [];
for i=1:length(interval_time)
    tmp_value = find(unique(years_0day)==interval_time(i));
    if tmp_value
        %if true means it found it therefore get the value in the index
        %position
        values_interval = [values_interval values_per_year(tmp_value)];
    else
        %missing therefore add a 0
        values_interval = [values_interval 0];
    end
end

figure
hold on
set(gca,'FontSize',12)
histogram(years_0day)
xlabel("Year")
ylabel("# vulnerabilities in *-Unknown scenarios")
set(gca, 'XTick', [min(interval_time):max(interval_time)])
set(gca, 'YTick', [0:max(values_per_year)+1])
ylim([0 max(values_per_year)+1])
xtickangle(45)
l_mean = yline(mean(values_per_year),'color','r','DisplayName','Mean');
legend([l_mean],{'Mean'})
print -depsc evolution-year-0days.eps

% clear stuff
clear apts_tmp cves_tmp final_tmp index l_mean tmp tmp_value


%% CAMPAIGN SECTION

%classification of campaigns based on the exploitation of the CVE (Before MITRE, Between MITRE and NVD, After
%NVD)
%we work only with the campaigns that exploited a CVE
before_mitre = [];
between_mitre_nvd = [];
after_nvd = [];

for i=1:length(campaigns_CVE)
    %extract the CVE exploited in the campaigns
    CVE_exploited = campaigns_vulns_vector_product_version_os(strcmp(campaigns_vulns_vector_product_version_os.('campaign'),campaigns_CVE(i)),:);
    %ignore info about product,version, etc so that we can count the unique
    %CVEs
    CVE_exploited = CVE_exploited(:,{'APT','campaign','vulnerability','attack_vector','exploited_time','published_time','reserved_time'});
    %drop duplicates
    CVE_exploited = unique(CVE_exploited);
    n_CVE = size(CVE_exploited,1);
    for j=1:n_CVE
        %check if it was before after or between
        if CVE_exploited.('exploited_time')(j)>=CVE_exploited.('published_time')(j)
            after_nvd = [after_nvd categorical(campaigns_CVE(i))];
        elseif CVE_exploited.('exploited_time')(j)<CVE_exploited.('reserved_time')(j)
            before_mitre = [before_mitre categorical(campaigns_CVE(i))];
        else
            between_mitre_nvd = [between_mitre_nvd categorical(campaigns_CVE(i))];
        end
    end
end

after_nvd = unique(after_nvd);
before_mitre = unique(before_mitre);
between_mitre_nvd = unique(between_mitre_nvd);


writematrix(between_mitre_nvd,'between.csv') 
writematrix(after_nvd,'after.csv') 
writematrix(before_mitre,'before.csv') 

%compute the number of campaigns that do not exploit CVEs and exploit CVE
fprintf("Number of campaigns that DO NOT EXPLOIT vulnerabilities:%d\n",length(campaigns_no_CVE))
fprintf("Number of campaigns that EXPLOIT vulnerabilities:%d\n",length(campaigns_CVE))
fprintf("Total number of campaigns:%d\n",length(tot_campaigns));


%compute number of campaigns for each attack vector
%we extract from the main table only the rows of interest (i.e. ignore
%version,product,etc.)
campaigns_info = unique(campaigns_vulns_vector_product_version_os(:,{'APT','campaign','vulnerability','attack_vector','exploited_time','published_time','reserved_time'}));
campaigns_with_SE = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Spearphishing ')));
n_campaign_with_SE = length(campaigns_with_SE);
campaigns_without_SE = setdiff(tot_campaigns,campaigns_with_SE);
campaigns_unknown = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Unknown')));
campaigns_with_valid = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Valid Accounts')));
campaigns_with_public = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Exploit Public-Facing Application')));
campaigns_with_remote = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'External Remote Services')));
campaigns_with_usb = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Replication Through Removable Media')));
campaigns_with_supply = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Supply Chain Compromise')));
campaigns_with_drive = unique(campaigns_info.('campaign')(contains(campaigns_info.('attack_vector'),'Drive-by Compromise')));
campaigns_only_unknown = setdiff(campaigns_unknown,campaigns_with_SE);
campaigns_no_SE_no_unknown = setdiff(campaigns_without_SE,campaigns_only_unknown);

fprintf("Campaigns Spearphishing w/o CVE:%d\n",length(intersect(campaigns_with_SE,campaigns_no_CVE)));
fprintf("Campaigns Spearphishing w CVE:%d\n",length(intersect(campaigns_with_SE,campaigns_CVE)));

fprintf("Campaigns Drive-by w/o CVE:%d\n",length(intersect(campaigns_with_drive,campaigns_no_CVE)));
fprintf("Campaigns Drive-by w CVE:%d\n",length(intersect(campaigns_with_drive,campaigns_CVE)));

fprintf("Campaigns Supply w/o CVE:%d\n",length(intersect(campaigns_with_supply,campaigns_no_CVE)));
fprintf("Campaigns Supply w CVE:%d\n",length(intersect(campaigns_with_supply,campaigns_CVE)));

fprintf("Campaigns Valid Account w/o CVE:%d\n",length(intersect(campaigns_with_valid,campaigns_no_CVE)));
fprintf("Campaigns Valid Account w CVE:%d\n",length(intersect(campaigns_with_valid,campaigns_CVE)));

fprintf("Campaigns External Remote Service w/o CVE:%d\n",length(intersect(campaigns_with_remote,campaigns_no_CVE)));
fprintf("Campaigns External Remote Service w CVE:%d\n",length(intersect(campaigns_with_remote,campaigns_CVE)));

fprintf("Campaigns Exploit Public Facing w/o CVE:%d\n",length(intersect(campaigns_with_public,campaigns_no_CVE)));
fprintf("Campaigns Exploit Public Facing w CVE:%d\n",length(intersect(campaigns_with_public,campaigns_CVE)));

fprintf("Campaigns Replication via Removable w/o CVE:%d\n",length(intersect(campaigns_with_usb,campaigns_no_CVE)));
fprintf("Campaigns Replication via Removable w CVE:%d\n",length(intersect(campaigns_with_usb,campaigns_CVE)));

fprintf("Campaigns Unknown w/o CVE:%d\n",length(intersect(campaigns_unknown,campaigns_no_CVE)));
fprintf("Campaigns Unknown w CVE:%d\n",length(intersect(campaigns_unknown,campaigns_CVE)));


%% APT SECTION

%plot 0-days/CVE per APT
%table that identify for each vuln exploited by an APT if it was 0-day or
%not

new_tab = table(apts_vulnerabilities.('APT'),apts_vulnerabilities.('CVE'),apts_vulnerabilities.('exploited_time')<(apts_vulnerabilities.('published_time')),apts_vulnerabilities.('exploited_time')>=(apts_vulnerabilities.('published_time')),'VariableNames',{'APT','CVE','zeroday','nozeroday'});
%drop duplicates: what does it means -> if we have that an APT exploit a
%CVE multiple times as 0-days they are still exploting that 0-day, so it is
%counted as one (and eliminated because duplicate).
%If the APT exploit a CVE multiple time first as 0-day and then as known it
%should be counted only the first time again
apts_with_CVE = unique(new_tab.('APT'));
my_new_tab = table();
for i=1:length(apts_with_CVE)
   %reduce to specific APT
   tmp_new_tab = new_tab(strcmp(new_tab.('APT'),apts_with_CVE(i)),:);
   %check if CVE exploited multiple times, if yes takes only the first one
   %(it is ordered by time of exploitation so we do not lose info)
   tmp_cves = unique(tmp_new_tab.('CVE'));
   for j=1:length(tmp_cves)
      %pick the first index only
      my_index = find(strcmp(tmp_new_tab.('CVE'),tmp_cves(j)),1,'first');
      %save in the new table
      my_new_tab = [my_new_tab;tmp_new_tab(my_index,:)];
   end
end
%put in the old one
new_tab = my_new_tab;

%plot scatter but with dimension=f(frequency of points in that position) 
%here we are plotting only those that exploited at least one CVE
value_x=[];
value_y=[];

for i=1:length(apts_with_CVE)
    cves = sum(new_tab.('nozeroday')(strcmp(new_tab.('APT'),apts_with_CVE(i))));
    zerodays = sum(new_tab.('zeroday')(strcmp(new_tab.('APT'),apts_with_CVE(i))));
    value_x= [value_x cves];
    value_y= [value_y zerodays];
end
observed_pairs = strcat(string(value_x),"-",string(value_y));
%count occurences
[frequency,pair] = histcounts(categorical(observed_pairs));
%now split them again and use the frequency as info
values = str2double(split(pair,"-"));
table_cve_0day_frequency = table(values(:,:,1)',values(:,:,2)',frequency','VariableNames',{'x_CVE','y_0day','frequency'});

figure
set(gca,'FontSize',12)
hold on
size_value = 15;
scatter(reshape(table_cve_0day_frequency.('x_CVE'),[],1),reshape(table_cve_0day_frequency.('y_0day'),[],1),size_value*((reshape(table_cve_0day_frequency.('frequency'),[],1)).^2),'filled','MarkerFaceAlpha',0.6,'MarkerEdgeColor',[0 0 0],'LineWidth',1.5);
text(reshape(table_cve_0day_frequency.('x_CVE')(table_cve_0day_frequency.('frequency')>1),[],1)+0.1,reshape(table_cve_0day_frequency.('y_0day')(table_cve_0day_frequency.('frequency')>1),[],1)+0.3,categorical(reshape(table_cve_0day_frequency.('frequency')(table_cve_0day_frequency.('frequency')>1),[],1)));
x = linspace(-2.5,13);
y = linspace(-2.5,13);
plot(x,y,'color',[0.8500 0.3250 0.0980]);
xlim([-2.5,13]);
xticks([0:13]);
ylim([-2.5,7.5]);
yticks([0:7]);
xline(0.5,'--r');
yline(6.5,'--r');
yline(0.5,'--r');
xlabel('# of known vulns exploited')
ylabel('# of unknown vulns exploited')
print -depsc zerodayAPTs.eps

%compute # of CVE exploited by each APT that are shared with
%other
n_dupl = [];
n_unique = [];
tmp_new_table = unique(table(apts_vulnerabilities.('APT'),apts_vulnerabilities.('CVE'),'VariableNames',{'APT','CVE'}));
for i=1:length(apts_with_CVE)
    n_duplicate = 0;
    %get list of CVE for each APT
    CVEs = tmp_new_table(strcmp(tmp_new_table.('APT'),apts_with_CVE(i)),:).('CVE');
    length_CVE = length(CVEs);
    %for each CVE check if it is not unique
    for j=1:length_CVE
        dupl_CVE = length(tmp_new_table(strcmp(tmp_new_table.('CVE'),CVEs(j)),:).('CVE'));
        if dupl_CVE>1
            n_duplicate = n_duplicate + 1;
        end
    end
    n_dupl = [n_dupl; n_duplicate];
    n_unique = [n_unique; length_CVE-n_duplicate];    
end

%merge in a table
table_APTs = table(apts_with_CVE,n_dupl,n_unique);

%count the frequency of the pairs shared-notshared
observed_pairs = strcat(string(n_dupl),"-",string(n_unique));
%count occurences
[frequency,pair] = histcounts(categorical(observed_pairs));
%now split them again and use the frequency as info
values = str2double(split(pair,"-"));
table_shared_unique_frequency = table(values(:,:,1)',values(:,:,2)',frequency','VariableNames',{'x_shared','y_unique','frequency'});

figure
set(gca,'FontSize',12)
hold on
size_value = 15;
scatter(reshape(table_shared_unique_frequency.('x_shared'),[],1),reshape(table_shared_unique_frequency.('y_unique'),[],1),size_value*((reshape(table_shared_unique_frequency.('frequency'),[],1)).^2),'filled','MarkerFaceAlpha',0.6,'MarkerEdgeColor',[0 0 0],'LineWidth',1.5);
text(reshape(table_shared_unique_frequency.('x_shared')(table_shared_unique_frequency.('frequency')>1),[],1)-0.05,reshape(table_shared_unique_frequency.('y_unique')(table_shared_unique_frequency.('frequency')>1),[],1)+0.3,categorical(reshape(table_shared_unique_frequency.('frequency')(table_shared_unique_frequency.('frequency')>1),[],1)),'Fontsize',12);
x = linspace(-2.5,11);
y = linspace(-2.5,11);
plot(x,y,'color',[0.8500 0.3250 0.0980]);
xticks([0:11])
yticks([0:10.5])
ylim([-2.5,10.5])
xlim([-2.5,10.5])
xline(0.5,'--r');
yline(9.5,'--r');
yline(0.5,'--r');
xlabel('Number of shared CVE')
ylabel('Number of not shared CVE')
print -depsc CVE-sharing.eps


clear my_index my_new_tab new_tab tmp_cves tmp_new_tab tmp_new_table

%% COMPARE EXPLOIT AGE AND CAMPAIGNS WITH PATCHING DELTA OF ENTERPRISES
%create a new table. It is more informative than campaigns_products as it
%includes CVEs and more time information
campaigns_vulns_products = unique(table(campaigns_vulns_vector_product_version_os.('APT'),campaigns_vulns_vector_product_version_os.('campaign'),campaigns_vulns_vector_product_version_os.('vulnerability'),campaigns_vulns_vector_product_version_os.('exploited_time'),campaigns_vulns_vector_product_version_os.('published_time'),campaigns_vulns_vector_product_version_os.('reserved_time'),campaigns_vulns_vector_product_version_os.('product')));
campaigns_vulns_products.Properties.VariableNames = {'APT','campaign','vulnerability','exploited_time','published_time','reserved_time','product'};
%drop line with empty products
campaigns_vulns_products(ismissing(campaigns_vulns_products.('product')),:)=[];

%Analyze products exploit age
average_exploit_time = [];
for i=1:length(products_paper)
    published_tmp = campaigns_vulns_products.('published_time')(contains(campaigns_vulns_products.('product'),products_paper(i)));
    exploited_tmp = campaigns_vulns_products.('exploited_time')(contains(campaigns_vulns_products.('product'),products_paper(i)));

    tmp_exploit = split(-between(datetime(exploited_tmp),datetime(published_tmp)),'months');
    average_exploit_time = [average_exploit_time mean(tmp_exploit)]; 
end

paper_product_exploit_age = table(products_paper',average_exploit_time','VariableNames',{'Product','AVG_Exploit_Age'})

%we focus only on *WINDOWS O.S.* campaigns that exploited a CVE
%first drop the lines without CVE
tmp_tmp = campaigns_vulns_vector_product_version_os(not(idx_missing_CVE),:);
%filter to those lines that affect windows O.S.
idx_windows_os = find(contains(tmp_tmp.('os'),'windows'));
%we also consider those that affect any O.S. because windows will be
%included
idx_any_os = find(strcmp(tmp_tmp.('os'),'*'));
idx_windows_os = unique([idx_windows_os;idx_any_os]);
campaigns_vulns_vector_product_version_windows = tmp_tmp(idx_windows_os,:);
%ignore the attack vector: this because we could have that the same CVE is
%exploited in different ways, we do not care for the simulation
campaigns_vulns_vector_product_version_windows.('attack_vector') = [];
campaigns_vulns_vector_product_version_windows = unique(campaigns_vulns_vector_product_version_windows);
clear tmp_tmp

%% CREATE TABLE THAT CONTAINS CAMPAIGNS, CVE, PRODUCT, AND MAX-MIN AFFECTED VERSION

cves_list = [];
products_list = [];
max_version_list = [];
min_version_list = [];
exploit_date_list = [];
published_date_list = [];
reserved_date_list = [];
campaigns = [];
for i=1:length(products_paper)
   %get the CVE associated to that product 
   CVEs_product = unique(campaigns_vulns_vector_product_version_windows.('vulnerability')(contains(campaigns_vulns_vector_product_version_windows.('product'),products_paper(i))));
   for j=1:length(CVEs_product)
      %for each CVE get the max version affected 
      %reduce on the product of interest to avoid to get versions of other
      %product affected by the same vuln
      limit_table_product = campaigns_vulns_vector_product_version_windows(contains(campaigns_vulns_vector_product_version_windows.('product'),products_paper(i)),:);
      %get the versions and the updates, join them and get the max version
      %affected
      tmp_versions = limit_table_product.('version')(strcmp(limit_table_product.('vulnerability'),CVEs_product(j)));
      tmp_updates = limit_table_product.('update')(strcmp(limit_table_product.('vulnerability'),CVEs_product(j)));
      %some versions could contain only e.g. '-' i.e. NA for NVD, let's ignore
      %them
      idx_NA = strcmp(tmp_versions,'-');
      tmp_versions(idx_NA)=[];
      tmp_updates(idx_NA)=[];
      %concat with the updates if any and then sort them and extract the
      %most recent one
      concatenated_versions_updates = strcat(tmp_versions,'-',tmp_updates);
      %use sort_nat and get the last value
      ordered_list = sort_nat(concatenated_versions_updates);
      %this is for office only
      %drop the office xp versions because crash the order. They are old so ignore
      %them
      idx_tmp = contains(ordered_list,'xp');
      ordered_list(idx_tmp)=[];
      %also drop some wrong versions due to bad data on NVD
      idx_tmp2 = strcmp(ordered_list,'--*');
      ordered_list(idx_tmp2)=[];
      
      %take min max now
      max_value = ordered_list(end);
      min_value = ordered_list(1);
      %get also the list of campaigns date_start that exploited the CVE
      exploited_time = campaigns_vulns_products.('exploited_time')(strcmp(campaigns_vulns_products.('vulnerability'),CVEs_product(j)));
      campaign = campaigns_vulns_products.('campaign')(strcmp(campaigns_vulns_products.('vulnerability'),CVEs_product(j)));
      published = campaigns_vulns_products.('published_time')(strcmp(campaigns_vulns_products.('vulnerability'),CVEs_product(j)));
      reserved = campaigns_vulns_products.('reserved_time')(strcmp(campaigns_vulns_products.('vulnerability'),CVEs_product(j)));
      
      size_campaigns = size(exploited_time,1);
      %add to the array
      cves_list = [cves_list;repmat(CVEs_product(j),size_campaigns,1)];
      products_list = [products_list;repmat(products_paper(i),size_campaigns,1)];
      max_version_list = [max_version_list;repmat(max_value,size_campaigns,1)];
      min_version_list = [min_version_list;repmat(min_value,size_campaigns,1)];
      exploit_date_list = [exploit_date_list;exploited_time];
      published_date_list = [published_date_list; published];
      reserved_date_list = [reserved_date_list; reserved];
      campaigns = [campaigns;campaign];
   end
end

table_versions_campaign = table(cves_list,products_list,max_version_list,min_version_list,exploit_date_list,published_date_list,reserved_date_list,campaigns,'VariableNames',{'cve','product','max_version','min_version','exploited_date','published_date','reserved_date','campaign'});
%the table could have some duplicates, eliminate them
table_versions_campaign = unique(table_versions_campaign,'stable');


%% SIMULATION OF PATCH STRATEGY
first_vulnerable = true; %this choice allows to define as the first installed version the first vulnerable version available in the list of updates

%choose between analyzing the combination of version in the interval or
%only the first vulnerable initial version
initial_vulnerable_analysis = true;


avg_patch_90_months = 3;
avg_patch_90=30*avg_patch_90_months;
optimistic = true;
fprintf("SIMULATION SETTINGS\n")
fprintf("#################\n")
fprintf("Patch Interval: %d months\n",avg_patch_90_months)
fprintf("Scenario Optimistic: %s\n",categorical(optimistic))
fprintf("Starting from *first* vulnerable version: %s\n",categorical(first_vulnerable))
fprintf("#################\n")

%get the min and max date to generate the timeline: our data are between
%2008 and 2020 so lets use this as interval of time
min_date = datetime("01/01/2008",'InputFormat','MM/dd/yyyy');

max_date = datetime("01/01/2020",'InputFormat','MM/dd/yyyy');

timeline = min_date:calmonths(1):max_date;

%create possible ranges of initial versions to start with
table_initial_versions = table();
%this is for the simulation by considering only the first vulnerable
%version
initial_and_vulnerable_version_single = [];
interval_range = 0.5; %4 years interval range i.e. if we have 02/2008 we will consider interval 02/2006 to 02/2010
for p=1:length(products_paper)
    product_specific_versions = unique(products_versions(strcmp(products_versions.('product'),products_paper(p)),:));
    product_specific_versions.('release_date')=datetime(product_specific_versions.('release_date'),'InputFormat','yyyy-MM');
    %drop all release that happen out of the time of interest
    product_specific_versions(product_specific_versions.('release_date')>max_date,:)=[];
    %IMPO: there could be still duplicate rows (this happen because e.g. a
    %same KB is updated over time (e.g. they updated a field and so the date is changed). Let's then take only the first date when
    %it was published
    %order ascending by release_date
    product_specific_versions = sortrows(product_specific_versions,3);
    %now drop the duplicates by ignoring the date
    [~,idx,~] = unique(product_specific_versions(:,1:2),'rows');
    product_specific_versions = product_specific_versions(idx,:);
    
    %reduce info about available version to the product of interest only
    tmp_campaigns_vulns_products_versions = campaigns_vulns_vector_product_version_windows(strcmp(campaigns_vulns_vector_product_version_windows.('product'),products_paper(p)),:);
    
    %we want to eliminate all the previous versions that are not affected
    %by a vuln so that all the strategies will start from the same version
    %first compute the vulnerable versions
    list_versions = tmp_campaigns_vulns_products_versions.('version')(contains(tmp_campaigns_vulns_products_versions.('product'),products_paper(p)));
    list_updates = tmp_campaigns_vulns_products_versions.('update')(contains(tmp_campaigns_vulns_products_versions.('product'),products_paper(p)));
    list_vulnerable = sort_nat(unique(strcat(list_versions,'-',list_updates)));
    
    product_specific_versions = sortrows(product_specific_versions,'release_date');
    
    if strcmp(products_paper(p),'office')
        %lets put the first version as the one w/o KB at the date of release of
        %Office 2016
        product_specific_versions = [{'office',"2016-*",datetime('2015-09-01'),''};product_specific_versions];
        first_vulnerable_and_available = product_specific_versions.('version')(1);
    else
        %search for the first available and vulnerable version BUT that is
        %published after the period of interest i.e. min_date
        after_mindate_product_specific_versions = product_specific_versions.('version')(product_specific_versions.('release_date')>=min_date);
        available_versions_vulnerable = sort_nat(intersect(after_mindate_product_specific_versions,list_vulnerable));
        first_vulnerable_and_available = available_versions_vulnerable(1);
    end
        %let's save this for the simulation with only the first vulnerable
        %and available version
        initial_and_vulnerable_version_single = [initial_and_vulnerable_version_single first_vulnerable_and_available];

        %now get the version in the range of +/- X years from this version
        %from the available (but not for sure vulnerable) versions
        %first get the date of the first_vulnerable_and_available version
        date_first_vulnerable_and_available = product_specific_versions.('release_date')(strcmp(product_specific_versions.('version'),first_vulnerable_and_available));
        %now get the interval of interest
        min_date_initial_version = date_first_vulnerable_and_available - years(interval_range/2);
        max_date_initial_version = date_first_vulnerable_and_available + years(interval_range/2);
        
        %extract the available version in this interval
        extractor_index = and(product_specific_versions.('release_date')>=min_date_initial_version,product_specific_versions.('release_date')<=max_date_initial_version);
        list_initial_versions = product_specific_versions.('version')(extractor_index);
        list_release_date = product_specific_versions.('release_date')(extractor_index);
        
        %add them to the table of initial versions
        table_initial_versions = [table_initial_versions;table(repmat(products_paper(p),length(list_initial_versions),1),list_initial_versions,list_release_date,'VariableNames',{'product','version','release_date'})];
end

%create all possible combinations of these initial versions for the
%products of interest
L = {};
for p=1:length(products_paper)
    L{end+1}= table_initial_versions.('version')(strcmp(table_initial_versions.('product'),products_paper(p)),:);
end

n = length(L);
[L{:}] = ndgrid(L{end:-1:1});
L = cat(n+1,L{:});
L = fliplr(reshape(L,[],n));


if initial_vulnerable_analysis
    L = initial_and_vulnerable_version_single;
end


cell_table_strategy_on_the_edge = {};
cell_table_strategy_autoupdate = {};
cell_table_strategy_reactive = {};
cell_table_strategy_informed_reactive = {};
cell_table_strategy_reactive_on_advisory = {};
cell_table_strategy_informed_reactive_on_advisory = {};

table_final_results = table();

%start creation of strategies based on different initial version for the
%different product, then multiply the strategies for the campaigns and
%compute odds, number of patches and probability of compromised

for r=1:size(L,1)
fprintf("Running simulation %d/%d\n",r,size(L,1))
table_strategy_on_the_edge = [];
table_strategy_autoupdate = [];
table_strategy_reactive = [];
table_strategy_informed_reactive = [];
table_strategy_reactive_on_advisory = [];
table_strategy_informed_reactive_on_advisory = [];
table_exploits = [];
table_timeline_exploitations = [];

products_vulns_versions = [];
unique_cves = [];
unique_campaigns = [];
unique_apts = [];
for p=1:length(products_paper)
    %first get the CVE exploited for the product
    table_versions_campaign_product = table_versions_campaign(strcmp(table_versions_campaign.('product'),products_paper(p)),:);

    %get the advisories and versions for the product
    products_advisories_product = products_advisories(strcmp(products_advisories.('product'),products_paper(p)),:);
    products_versions_product = products_versions(strcmp(products_versions.('product'),products_paper(p)),:);
    
    if strcmp(products_paper(p),'office')
        %for office we are currently simulating only office 2016 thus ignore
        %other campaigns for the moment
        fprintf("Ignoring campaigns that do not affect Office 2016...\n")
        array_true = [];
        for d=1:size(table_versions_campaign_product,1)
            sorted = sort_nat([table_versions_campaign_product.('min_version')(d) '2016-*']);
            if strcmp(sorted(end),'2016-*')
                sorted = sort_nat([table_versions_campaign_product.('max_version')(d) '2016-*']);
                if strcmp(sorted(1),'2016-*')
                    array_true = [array_true;1];
                else
                   array_true = [array_true;0]; 
                end
            else
                array_true = [array_true;0]; 
            end
        end
    array_true = logical(array_true);
    table_versions_campaign_product = table_versions_campaign_product(array_true,:);
    end
    
    [unique_cves,unique_campaigns,unique_apts] = statistics_simulation(unique_cves,unique_campaigns,unique_apts,table_versions_campaign_product,campaigns_vulns_vector_product_version_windows);
    
    %load the CVEs exploited by the APT
    cves_exploited = unique(table_versions_campaign_product.('cve'));
    %load all CVEs affecting the products of interest
    all_cves = unique(all_vulns_tab.('CVE'));
    
    product_specific_versions = unique(products_versions(strcmp(products_versions.('product'),products_paper(p)),:));
    product_specific_versions.('release_date')=datetime(product_specific_versions.('release_date'),'InputFormat','yyyy-MM');
    %drop version released after the last date of interest
    product_specific_versions(product_specific_versions.('release_date')>max_date,:)=[];
    %IMPO: there could be still duplicate rows (this happen because e.g. a
    %same KB is updated over time (e.g. they updated a field and so the date is changed). Let's then take only the first date when
    %it was published
    %order ascending by release_date
    product_specific_versions = sortrows(product_specific_versions,3);
    %now drop the duplicates by ignoring the date
    [~,idx,~] = unique(product_specific_versions(:,1:2),'rows');
    product_specific_versions = product_specific_versions(idx,:);
    
    %reduce info about available version to the product of interest only
    tmp_campaigns_vulns_products_versions = campaigns_vulns_vector_product_version_windows(strcmp(campaigns_vulns_vector_product_version_windows.('product'),products_paper(p)),:);
    products_vulns_versions = [products_vulns_versions; tmp_campaigns_vulns_products_versions];
    
    %we want to eliminate all the previous versions that are not affected
    %by a vuln so that all the strategies will start from the same version
    %first compute the vulnerable versions
    list_versions = tmp_campaigns_vulns_products_versions.('version')(contains(tmp_campaigns_vulns_products_versions.('product'),products_paper(p)));
    list_updates = tmp_campaigns_vulns_products_versions.('update')(contains(tmp_campaigns_vulns_products_versions.('product'),products_paper(p)));
    list_vulnerable = sort_nat(unique(strcat(list_versions,'-',list_updates)));
    
    %we first sort by version and then by release, this is to avoid to
    %install a older version that is release later than another.
    %this can happen e.g. jre 1.6u6 and 1.5u16. If one jump to a new
    %version 1.6 should not go back to 1.5 even if the update is newer
    if ~strcmp(products_paper(p),'office')
        %sort first based on version
        [a,index_versioning] = sort_nat(product_specific_versions.('version'));
        product_specific_versions = product_specific_versions(index_versioning,:);
    else
        %if it is office in this case the KB have a number that is not
        %linked to new release so we base only on the release date
        product_specific_versions = sortrows(product_specific_versions,'release_date');
    end
    
    if strcmp(products_paper(p),'office')
    %lets put the first version as the one w/o KB at the date of release of
    %Office 2016
        product_specific_versions = [{'office',"2016-*",datetime('2015-09-01'),''};product_specific_versions];
    end    
    
    %select the initial version from the pool
    initial_version = L(r,p);
    %reduce the list to the initial version
    begin_index = find(strcmp(product_specific_versions.('version'),initial_version));
    %drop the previous lines only
    product_specific_versions = product_specific_versions(begin_index:end,:);
            
            
    %create first strategy: patch as soon as a new release is available:
    %IMMEDIATE strategy
    tmp_table_versions = [];
    for i=1:size(product_specific_versions,1)
        %find for each date of publication, which other dates in the timeline are greater or
        %equal to it
        line = double(timeline>=product_specific_versions.('release_date')(i));
        tmp_table_versions = [tmp_table_versions;line];
    end
    %now we need to eliminate the 1s when a newer version is available. We can
    %just subtract the n-th row to ALL previous n-1-th rows
    %first save this table because it describes which versions are
    %available from now on (used later to compute the last strategy)
    availability_releases = tmp_table_versions;
    for i=size(tmp_table_versions,1):-1:2
        tmp_table_versions(1:i-1,:) = tmp_table_versions(1:i-1,:)-tmp_table_versions(i,:);
        tmp_table_versions(tmp_table_versions<0)=0;
    end
    
    %FINALLY: force the strategy to start with the first version vulnerable
    %i.e. the first line (this will be the same for the reactive strategy)
    %so that the simulation is coherent and use the same starting point,
    %then the procedure of update will work as usual and you will jump to
    %the new one
    %we need to add a column with a 1 and all 0 from the time the release
    %is available if is greater than the starting timeline, otherwise at
    %the first column
    if product_specific_versions.('release_date')(1)<timeline(1)
        %overwrite the first column and stop
        tmp_table_versions(:,1)=[1;zeros(size(tmp_table_versions,1)-1,1)];
    else
        %else find the index in the timeline
        index_column = find(product_specific_versions.('release_date')(1)==timeline);
        tmp_table_versions(:,index_column)=[1;zeros(size(tmp_table_versions,1)-1,1)];
        %whatever it is before should be zero
        tmp_table_versions(:,[1:index_column-1])=zeros(size(tmp_table_versions,1),index_column-1);
    end
    
    %check if we are simulating the optimistic scenario (i.e. if campaign
    %and patch happen at the same time, the patch is applied first) or the
    %pessimistic scenario (opposite result)
    if not(optimistic)
        %lets assume a worst scenario where the patch is done some time later
        %in the month so possible exploitation in that month are still able to
        %reach the older version
        for i=size(tmp_table_versions,1):-1:2
            %find the first column that has a 1
            id_column=find(tmp_table_versions(i,:)>0,1);
            %if we found one let's search for the line before it that has a
            %1
            if not(isempty(id_column))
                %goal: put a one to the line that has the 1 before this one
                %(could not be the previous line) so start the search from
                %the previous line on
                for j=i-1:-1:1
                    tmp=find(tmp_table_versions(j,:)>0,1);
                    if not(isempty(tmp))
                        %found the first line that has the ones before that
                        %one. Here we put 1 on this line with the column
                        %previously found
                        tmp_table_versions(j,id_column)=1;
                        break
                    end
                end
            end
        end
    end
    
    %compute matrix for second strategy, i.e. first strategy with a delay of
    %X months
    %PLANNED strategy

    %it a bit complicated because not all the products have a one (i.e.
    %release) at the first date of the timeline therefore we risk adding 1
    %at the beginning to change the timeline of release, thus
    %first find the index of the first 1 on the first release, shift only
    %that part of the matrix and then attach the previous one with the
    %updated and shifted one
    
    %it is possible that the first line is all 0s because another newer release
    %is present in the same date too. Lets find the first row with a one
    %and get the index from that row
    [row,column] = find(tmp_table_versions);
    index = find(tmp_table_versions(row(1),:),1);
    
    %first a circular shift
    shifted_array = circshift(tmp_table_versions(:,index:end),avg_patch_90_months,2);
    %however the values that overflow on the right come back to the left, here
    %so we need to clean the overflowed to zero and then add the ones only
    %on the row of the current installed version
    %clean it first
    shifted_array(:,1:avg_patch_90_months) = zeros(size(shifted_array,1),avg_patch_90_months);
    %add the ones
    shifted_array(row(1),1:avg_patch_90_months) = ones(1,avg_patch_90_months);
    
    %at this point reattach the remaining vector that we ignored to shift
    shifted_array = [tmp_table_versions(:,1:index-1) shifted_array];
    
    %for the pessimistic scenarion here we already relying on
    %tmp_table_versions has already the pessimistic scenario
    
    
    %compute the matrix of the third strategy:
    %REACTIVE strategy (i.e. patch when a CVE is published by NVD)
    %get the list of affected versions for the CVE -> list_vulnerable
    %computed before
    
    %order them and get the first one (that is also present in the release), this will be the starting version of
    %this strategy from the publication
    matrix_reactive = zeros(size(product_specific_versions,1),length(timeline));
    %find the right row
    index = find(strcmp(product_specific_versions.('version'),initial_version));
    matrix_reactive(index,:) = matrix_reactive(index,:) + double(timeline>=product_specific_versions.('release_date')(strcmp(product_specific_versions.('version'),initial_version)));
    
    
    %for each cve get the patch that we must apply
    for i=1:length(cves_exploited)
        if strcmp(products_paper(p),'office')
            %here it is different than on the other products. We have a KB that
            %patch the CVE and not the maximum version vulnerable. Thus let's
            %find the KB that patch the CVE and then apply it as the new
            %version to install
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(table_versions_campaign_product.('published_date')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i)))));
            %get KBs for the CVE
            kb_indexes = find(strcmp(office2016_versions.('advisory'),cves_exploited(i)));
            %we could have multiple KB, we then take only the most recent
            %one BY RELEASE DATE BECAUSE KB numbering is not linked to more
            %recent!!!!
            if length(kb_indexes)>1
                tmp_kb_indexes = table(kb_indexes,office2016_versions.('release_date')(kb_indexes));
                kb_index = tmp_kb_indexes{end,1};
            else
                kb_index = kb_indexes;
            end
            %extract the kb names FROM THE office2016_versions because it
            %is different from the product_specific_versions file
            kbs = strcat(office2016_versions.('version')(kb_index),'-',office2016_versions.('update')(kb_index));
            %now extract only the most recent KBs
            kbs = sort_nat(kbs);
            my_version = kbs(end);
        else
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(table_versions_campaign_product.('published_date')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i)))));
            %get max version affected
            max_affected = unique(table_versions_campaign_product.('max_version')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i))));
            %search the next version not affected from this vuln
            vect_releases = sort_nat(unique([max_affected;product_specific_versions.('version')]));
            tmp_index = find(strcmp(vect_releases,max_affected));
            if tmp_index==length(vect_releases)
                %there is not a new version non vulnerable available, just updated to this one
                my_version = vect_releases(tmp_index);
            else
                my_version = vect_releases(tmp_index+1);
            end
        end
        %fill with ones from the publication of the CVE+delay on
        index = find(strcmp(product_specific_versions.('version'),my_version)); 
        matrix_reactive(index,:) = matrix_reactive(index,:) + double(timeline>=(datetime(dates)+calmonths(avg_patch_90_months)));
    end
    
    %now a certain version we choose could not be available yet.
    %In this case the patch_time must be considered from the time when the release is available
    %because it represent the set of actions required to check that the
    %update does not break anything.
    %Thus multiply the matrix with the release one. However the release one must be shifted
    %of the patch time delay we have so that if a version is not
    %available at the time we decided to update we will have a 0 up to the
    %point where the release + patch time is available
    shift_availability_releases = circshift(availability_releases,avg_patch_90_months,2);
    %again drop the 1s that enter from the left
    shift_availability_releases(:,1:avg_patch_90_months) = zeros(size(shift_availability_releases,1),avg_patch_90_months);
    
    matrix_reactive = matrix_reactive.*shift_availability_releases;
    %normalize to 1 because here we sum up (before by iterative over the CVEs) thus we could have value > 1
    matrix_reactive(matrix_reactive>1)=1;
    
    %now we need to eliminate the 1s when a newer version is installed. We can
    %just subtract the n-th row to ALL previous n-1-th rows
    for i=size(matrix_reactive,1):-1:2
        matrix_reactive(1:i-1,:) = matrix_reactive(1:i-1,:)-matrix_reactive(i,:);
        %unfortunately this will subtract also in rows where there is not one
        %(because we "jump" to the newer version not affected), thus change all
        %the -1 to 0
        %here we first need to set to zero every entry that is now negative
        %otherwise we will do --1 i.e. +1 and we will add them where we
        %shouldn't
        matrix_reactive(matrix_reactive==-1)=0;
    end
    
    
    %in this strategy we need to apply or not the pessimistic scenario
    
    %check if we are simulating the optimistic scenario (i.e. if campaign
    %and patch happen at the same time, the patch is applied first) or the
    %pessimistic scenario (opposite result)
    if not(optimistic)
        %lets assume a worst scenario where the patch is done some time later
        %in the month so possible exploitation in that month are still able to
        %reach the older version
        for i=size(matrix_reactive,1):-1:2
            %find the first column that has a 1
            id_column=find(matrix_reactive(i,:)>0,1);
            %if we found one let's search for the line before it that has a
            %1
            if not(isempty(id_column))
                %goal: put a one to the line that has the 1 before this one
                %(could not be the previous line) so start the search from
                %the previous line on
                for j=i-1:-1:1
                    tmp=find(matrix_reactive(j,:)>0,1);
                    if not(isempty(tmp))
                        %found the first line that has the ones before that
                        %one. Here we put 1 on this line with the column
                        %previously found
                        matrix_reactive(j,id_column)=1;
                        break
                    end
                end
            end
        end
    end    
    
    
    %create the fourth strategy: we patch as soon as an entry for a CVE is reserved in MITRE + a certain delay
    %INFORMED REACTIVE strategy
    
    %order them and get the first one (that is also present in the release), this will be the starting version of
    %this strategy from the publication
    matrix_reactive_mitre = zeros(size(product_specific_versions,1),length(timeline));
    %find the right row
    index = find(strcmp(product_specific_versions.('version'),initial_version));
    %let's start when it was officially release the version (for office
    %2016 too)
    matrix_reactive_mitre(index,:) = matrix_reactive_mitre(index,:) + double(timeline>=product_specific_versions.('release_date')(strcmp(product_specific_versions.('version'),initial_version)));
    
    %for each cve get the max vuln version
    for i=1:length(cves_exploited)
        if strcmp(products_paper(p),'office')
            %get reserved date of CVE
            dates = unique(string(table_versions_campaign_product.('reserved_date')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i)))));
            %get KBs for the CVE
            kb_indexes = find(strcmp(office2016_versions.('advisory'),cves_exploited(i)));
            %we could have multiple KB, we then take only the most recent
            %one BY RELEASE DATE BECAUSE KB numbering is not linked to more
            %recent!!!!
            if length(kb_indexes)>1
                tmp_kb_indexes = table(kb_indexes,office2016_versions.('release_date')(kb_indexes));
                kb_index = tmp_kb_indexes{end,1};
            else
                kb_index = kb_indexes;
            end
            %extract the kb names FROM THE office2016_versions because it
            %is different from the product_specific_versions file
            kbs = strcat(office2016_versions.('version')(kb_index),'-',office2016_versions.('update')(kb_index));
            %now extract only the most recent KBs
            kbs = sort_nat(kbs);
            my_version = kbs(end);
        else    
            %it is a single one for sure. Depending if is one of the CVEs
            %exploited between MITRE and NVD we get the reserved or the
            %published date
            %if ismember(cves(i),cves_between_mitre_nvd)
            dates = unique(string(table_versions_campaign_product.('reserved_date')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i)))));
            %else
            %    dates = unique(string(table_versions_campaign_product.('published_date')(strcmp(table_versions_campaign_product.('cve'),cves(i)))));
            %end
            %get max version affected
            max_affected = unique(table_versions_campaign_product.('max_version')(strcmp(table_versions_campaign_product.('cve'),cves_exploited(i))));
            %search the next version not affected from this vuln
            vect_releases = sort_nat(unique([max_affected;product_specific_versions.('version')]));
            tmp_index = find(strcmp(vect_releases,max_affected));
            if tmp_index==length(vect_releases)
                %there is not a new version non vulnerable available, just updated to this one
                my_version = vect_releases(tmp_index);
            else
                my_version = vect_releases(tmp_index+1);
            end
        end
        %fill with ones from the publication of the CVE+delay on
        index = find(strcmp(product_specific_versions.('version'),my_version)); 
        matrix_reactive_mitre(index,:) = matrix_reactive_mitre(index,:) + double(timeline>=(datetime(dates)+calmonths(avg_patch_90_months)));
    end
    
    
    %now a certain version we choose could not be available yet.
    %In this case the patch_time must be considered from the time when the release is available
    %because it represent the set of actions required to check that the
    %update does not break anything.
    %Thus multiply the matrix with the release one. However the release one must be shifted
    %of the patch time delay we have so that if a version is not
    %available at the time we decided to update we will have a 0 up to the
    %point where the release + patch time is available
    matrix_reactive_mitre = matrix_reactive_mitre.*shift_availability_releases;
    %normalize to 1 because here we sum up thus we could have value > 1
    matrix_reactive_mitre(matrix_reactive_mitre>1)=1;
    
    %now we need to eliminate the 1s when a newer version is installed. We can
    %just subtract the n-th row to ALL previous n-1-th rows
    for i=size(matrix_reactive_mitre,1):-1:2
        matrix_reactive_mitre(1:i-1,:) = matrix_reactive_mitre(1:i-1,:)-matrix_reactive_mitre(i,:);
        %unfortunately this will subtract also in rows where there is not one
        %(because we "jump" to the newer version not affected), thus change all
        %the -1 to 0
        %here we first need to set to zero every entry that is now negative
        %otherwise we will do --1 i.e. +1 and we will add them where we
        %shouldn't
        matrix_reactive_mitre(matrix_reactive_mitre==-1)=0;
    end
    
    %check if we are simulating the optimistic scenario (i.e. if campaign
    %and patch happen at the same time, the patch is applied first) or the
    %pessimistic scenario (opposite result)
    if not(optimistic)
        %lets assume a worst scenario where the patch is done some time later
        %in the month so possible exploitation in that month are still able to
        %reach the older version
        for i=size(matrix_reactive_mitre,1):-1:2
            %find the first column that has a 1
            id_column=find(matrix_reactive_mitre(i,:)>0,1);
            %if we found one let's search for the line before it that has a
            %1
            if not(isempty(id_column))
                %goal: put a one to the line that has the 1 before this one
                %(could not be the previous line) so start the search from
                %the previous line on
                for j=i-1:-1:1
                    tmp=find(matrix_reactive_mitre(j,:)>0,1);
                    if not(isempty(tmp))
                        %found the first line that has the ones before that
                        %one. Here we put 1 on this line with the column
                        %previously found
                        matrix_reactive_mitre(j,id_column)=1;
                        break
                    end
                end
            end
        end
    end

    %##################################
    %now compute the REACTIVE AND INFORMED REACTIVE BASED ONLY ON THE NVD
    %PUBLICATION AND THE ADVISORY OF THE VENDOR

    %REACTIVE ON ADVISORY ONLY (no knowledge of exploitation)
    %thus iterate over all CVEs
    %order them and get the first one (that is also present in the release), this will be the starting version of
    %this strategy from the publication
    matrix_reactive_on_advisory = zeros(size(product_specific_versions,1),length(timeline));
    %find the right row
    index = find(strcmp(product_specific_versions.('version'),initial_version));
    matrix_reactive_on_advisory(index,:) = matrix_reactive_on_advisory(index,:) + double(timeline>=product_specific_versions.('release_date')(strcmp(product_specific_versions.('version'),initial_version)));
    
    
    %for each cve get the patch that we must apply
    for i=1:length(all_cves)
        if strcmp(products_paper(p),'office')
            %here it is different than on the other products. We have a KB that
            %patch the CVE and not the maximum version vulnerable. Thus let's
            %find the KB that patch the CVE and then a  pply it as the new
            %version to install
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(all_vulns_tab.('publishedDate')(strcmp(all_vulns_tab.('CVE'),all_cves(i)))));
            %get KBs for the CVE
            kb_indexes = find(strcmp(office2016_versions.('advisory'),all_cves(i)));
            %if it is not related to office, skip
            if isempty(kb_indexes)
               continue
            end
            %we could have multiple KB, we then take only the most recent
            %one BY RELEASE DATE BECAUSE KB numbering is not linked to more
            %recent!!!!
            if length(kb_indexes)>1
                tmp_kb_indexes = table(kb_indexes,office2016_versions.('release_date')(kb_indexes));
                kb_index = tmp_kb_indexes{end,1};
            else
                kb_index = kb_indexes;
            end
            %extract the kb names FROM THE office2016_versions because it
            %is different from the product_specific_versions file
            kbs = strcat(office2016_versions.('version')(kb_index),'-',office2016_versions.('update')(kb_index));
            %now extract only the most recent KBs
            kbs = sort_nat(kbs);
            my_version = kbs(end);
        else
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(all_vulns_tab.('publishedDate')(strcmp(all_vulns_tab.('CVE'),all_cves(i)))));
            advisory = unique(products_advisories_product.('advisory')(strcmp(products_advisories_product.('cve'),all_cves(i))));
            %check if the advisory exist, if not this is a CVE that does
            %not affect this product
            if isempty(advisory)
                %move to the next CVE
                continue
            end
            %could be multiple advisory for the same CVE
            %keep the most recent one
            advisory = sort_nat(advisory);
            advisory = advisory(end);
            my_version = products_versions_product.('version')(strcmp(products_versions_product.('advisory'),advisory));
            if isempty(my_version)
                %move to the next CVE
                continue
            end
            %if the advisory covers more releases, order them and keep the
            %newest one. in this case we have that increasing number is
            %more recent advisory 
            my_version = sort_nat(my_version);
            %keep the most recent
            my_version = my_version(end);
        end
        %fill with ones from the publication of the CVE+delay on
        index = find(strcmp(product_specific_versions.('version'),my_version)); 
        matrix_reactive_on_advisory(index,:) = matrix_reactive_on_advisory(index,:) + double(timeline>=(datetime(dates)+calmonths(avg_patch_90_months)));
    end
    
    %now a certain version we choose could not be available yet.
    %In this case the patch_time must be considered from the time when the release is available
    %because it represent the set of actions required to check that the
    %update does not break anything.
    %Thus multiply the matrix with the release one. However the release one must be shifted
    %of the patch time delay we have so that if a version is not
    %available at the time we decided to update we will have a 0 up to the
    %point where the release + patch time is available
    shift_availability_releases = circshift(availability_releases,avg_patch_90_months,2);
    %again drop the 1s that enter from the left
    shift_availability_releases(:,1:avg_patch_90_months) = zeros(size(shift_availability_releases,1),avg_patch_90_months);
    
    matrix_reactive_on_advisory = matrix_reactive_on_advisory.*shift_availability_releases;
    %normalize to 1 because here we sum up (before by iterative over the all_cves) thus we could have value > 1
    matrix_reactive_on_advisory(matrix_reactive_on_advisory>1)=1;
    
    %now we need to eliminate the 1s when a newer version is installed. We can
    %just subtract the n-th row to ALL previous n-1-th rows
    for i=size(matrix_reactive_on_advisory,1):-1:2
        matrix_reactive_on_advisory(1:i-1,:) = matrix_reactive_on_advisory(1:i-1,:)-matrix_reactive_on_advisory(i,:);
        %unfortunately this will subtract also in rows where there is not one
        %(because we "jump" to the newer version not affected), thus change all
        %the -1 to 0
        %here we first need to set to zero every entry that is now negative
        %otherwise we will do --1 i.e. +1 and we will add them where we
        %shouldn't
        matrix_reactive_on_advisory(matrix_reactive_on_advisory==-1)=0;
    end
    
    
    %in this strategy we need to apply or not the pessimistic scenario
    
    %check if we are simulating the optimistic scenario (i.e. if campaign
    %and patch happen at the same time, the patch is applied first) or the
    %pessimistic scenario (opposite result)
    if not(optimistic)
        %lets assume a worst scenario where the patch is done some time later
        %in the month so possible exploitation in that month are still able to
        %reach the older version
        for i=size(matrix_reactive_on_advisory,1):-1:2
            %find the first column that has a 1
            id_column=find(matrix_reactive_on_advisory(i,:)>0,1);
            %if we found one let's search for the line before it that has a
            %1
            if not(isempty(id_column))
                %goal: put a one to the line that has the 1 before this one
                %(could not be the previous line) so start the search from
                %the previous line on
                for j=i-1:-1:1
                    tmp=find(matrix_reactive_on_advisory(j,:)>0,1);
                    if not(isempty(tmp))
                        %found the first line that has the ones before that
                        %one. Here we put 1 on this line with the column
                        %previously found
                        matrix_reactive_on_advisory(j,id_column)=1;
                        break
                    end
                end
            end
        end
    end    
    
    
    %create the fourth strategy: we patch as soon as an entry for a CVE is reserved in MITRE + a certain delay
    %INFORMED REACTIVE ON ADVISORY ONLY (no knowledge of exploitation)
    %thus iterate over all CVEs
    
    %order them and get the first one (that is also present in the release), this will be the starting version of
    %this strategy from the publication
    matrix_reactive_mitre_on_advisory = zeros(size(product_specific_versions,1),length(timeline));
    %find the right row
    index = find(strcmp(product_specific_versions.('version'),initial_version));
    %let's start when it was officially release the version (for office
    %2016 too)
    matrix_reactive_mitre_on_advisory(index,:) = matrix_reactive_mitre_on_advisory(index,:) + double(timeline>=product_specific_versions.('release_date')(strcmp(product_specific_versions.('version'),initial_version)));
    
    %for each cve get the max vuln version
    for i=1:length(all_cves)
        if strcmp(products_paper(p),'office')
            %here it is different than on the other products. We have a KB that
            %patch the CVE and not the maximum version vulnerable. Thus let's
            %find the KB that patch the CVE and then a  pply it as the new
            %version to install
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(all_vulns_tab.('reservedDate')(strcmp(all_vulns_tab.('CVE'),all_cves(i)))));
            %get KBs for the CVE
            kb_indexes = find(strcmp(office2016_versions.('advisory'),all_cves(i)));
            %if it is not related to office, skip
            if isempty(kb_indexes)
               continue
            end
            %we could have multiple KB, we then take only the most recent
            %one BY RELEASE DATE BECAUSE KB numbering is not linked to more
            %recent!!!!
            if length(kb_indexes)>1
                tmp_kb_indexes = table(kb_indexes,office2016_versions.('release_date')(kb_indexes));
                kb_index = tmp_kb_indexes{end,1};
            else
                kb_index = kb_indexes;
            end
            %extract the kb names FROM THE office2016_versions because it
            %is different from the product_specific_versions file
            kbs = strcat(office2016_versions.('version')(kb_index),'-',office2016_versions.('update')(kb_index));
            %now extract only the most recent KBs
            kbs = sort_nat(kbs);
            my_version = kbs(end);
        else
            %it is a single one for sure (single publication date for a CVE)
            dates = unique(string(all_vulns_tab.('reservedDate')(strcmp(all_vulns_tab.('CVE'),all_cves(i)))));
            advisory = unique(products_advisories_product.('advisory')(strcmp(products_advisories_product.('cve'),all_cves(i))));
            %check if the advisory exist, if not this is a CVE that does
            %not affect this product
            if isempty(advisory)
                %move to the next CVE
                continue
            end
            %could be multiple advisory for the same CVE
            %keep the most recent one
            advisory = sort_nat(advisory);
            advisory = advisory(end);
            my_version = products_versions_product.('version')(strcmp(products_versions_product.('advisory'),advisory));
            if isempty(my_version)
                %move to the next CVE
                continue
            end
            %if the advisory covers more releases, order them and keep the
            %newest one
            my_version = sort_nat(my_version);
            %keep the most recent
            my_version = my_version(end);
        end
        %fill with ones from the publication of the CVE+delay on
        index = find(strcmp(product_specific_versions.('version'),my_version)); 
        matrix_reactive_mitre_on_advisory(index,:) = matrix_reactive_mitre_on_advisory(index,:) + double(timeline>=(datetime(dates)+calmonths(avg_patch_90_months)));
    end
    
    
    %now a certain version we choose could not be available yet.
    %In this case the patch_time must be considered from the time when the release is available
    %because it represent the set of actions required to check that the
    %update does not break anything.
    %Thus multiply the matrix with the release one. However the release one must be shifted
    %of the patch time delay we have so that if a version is not
    %available at the time we decided to update we will have a 0 up to the
    %point where the release + patch time is available
    matrix_reactive_mitre_on_advisory = matrix_reactive_mitre_on_advisory.*shift_availability_releases;
    %normalize to 1 because here we sum up thus we could have value > 1
    matrix_reactive_mitre_on_advisory(matrix_reactive_mitre_on_advisory>1)=1;
    
    %now we need to eliminate the 1s when a newer version is installed. We can
    %just subtract the n-th row to ALL previous n-1-th rows
    for i=size(matrix_reactive_mitre_on_advisory,1):-1:2
        matrix_reactive_mitre_on_advisory(1:i-1,:) = matrix_reactive_mitre_on_advisory(1:i-1,:)-matrix_reactive_mitre_on_advisory(i,:);
        %unfortunately this will subtract also in rows where there is not one
        %(because we "jump" to the newer version not affected), thus change all
        %the -1 to 0
        %here we first need to set to zero every entry that is now negative
        %otherwise we will do --1 i.e. +1 and we will add them where we
        %shouldn't
        matrix_reactive_mitre_on_advisory(matrix_reactive_mitre_on_advisory==-1)=0;
    end
    
    %check if we are simulating the optimistic scenario (i.e. if campaign
    %and patch happen at the same time, the patch is applied first) or the
    %pessimistic scenario (opposite result)
    if not(optimistic)
        %lets assume a worst scenario where the patch is done some time later
        %in the month so possible exploitation in that month are still able to
        %reach the older version
        for i=size(matrix_reactive_mitre_on_advisory,1):-1:2
            %find the first column that has a 1
            id_column=find(matrix_reactive_mitre_on_advisory(i,:)>0,1);
            %if we found one let's search for the line before it that has a
            %1
            if not(isempty(id_column))
                %goal: put a one to the line that has the 1 before this one
                %(could not be the previous line) so start the search from
                %the previous line on
                for j=i-1:-1:1
                    tmp=find(matrix_reactive_mitre_on_advisory(j,:)>0,1);
                    if not(isempty(tmp))
                        %found the first line that has the ones before that
                        %one. Here we put 1 on this line with the column
                        %previously found
                        matrix_reactive_mitre_on_advisory(j,id_column)=1;
                        break
                    end
                end
            end
        end
    end

    
    %create table for first strategy
    T = array2table(tmp_table_versions);
    T.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_on_the_edge = [table_strategy_on_the_edge; T];
    
    %create table for second strategy
    T_2 = array2table(shifted_array);
    T_2.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_autoupdate = [table_strategy_autoupdate; T_2];
    
    %create table for reactive strategy
    T_3 = array2table(matrix_reactive);
    T_3.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_reactive = [table_strategy_reactive; T_3];
    
    %create table for mitre strategy
    T_4 = array2table(matrix_reactive_mitre);
    T_4.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_informed_reactive = [table_strategy_informed_reactive; T_4];

    %create table for reactive strategy with advisory
    T_5 = array2table(matrix_reactive_on_advisory);
    T_5.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_reactive_on_advisory = [table_strategy_reactive_on_advisory; T_5];

    %create table for mitre strategy with advisory
    T_6 = array2table(matrix_reactive_mitre_on_advisory);
    T_6.Properties.RowNames = strcat(product_specific_versions.('product'),'-',product_specific_versions.('version'));
    table_strategy_informed_reactive_on_advisory = [table_strategy_informed_reactive_on_advisory; T_6];

end
cell_table_strategy_on_the_edge{end+1}=table_strategy_on_the_edge;
cell_table_strategy_autoupdate{end+1}=table_strategy_autoupdate;
cell_table_strategy_reactive{end+1}=table_strategy_reactive;
cell_table_strategy_informed_reactive{end+1}=table_strategy_informed_reactive;
cell_table_strategy_reactive_on_advisory{end+1}=table_strategy_reactive_on_advisory;
cell_table_strategy_informed_reactive_on_advisory{end+1}=table_strategy_informed_reactive_on_advisory;

%now iterate over the different available table_strategy w/ different
%initial version

%create array that contains at each instant of time the number of
%active campaigns, and the number of campaigns for which each strategy is
%vulnerable
timeline_exploitations = zeros(1,size(timeline,2));

tot_vulns_strategy_on_the_edge = zeros(1,size(timeline,2));
tot_vulns_strategy_autoupdate = zeros(1,size(timeline,2));
tot_vulns_strategy_reactive = zeros(1,size(timeline,2));
tot_vulns_strategy_informed_reactive = zeros(1,size(timeline,2));
tot_vulns_strategy_reactive_on_advisory = zeros(1,size(timeline,2));
tot_vulns_strategy_informed_reactive_on_advisory = zeros(1,size(timeline,2));

%compute matrix of exploits affecting specific versions of the product
%we sum the campaigns one over the other i.e. if an entry is covered by two
%campaigns we must write two -> done summing matrixes
%begin with a zeros matrix
matrix_campaigns = zeros(size(table_strategy_on_the_edge,1),length(timeline));

%for the moment we focus on office 2016 but here we have also campaigns
%that affect only previous versions (that we treated as a different
%product) thus let's ignore those campaigns

fprintf("Ignoring campaigns that do not affect Office 2016...\n")
array_true = [];
for d=1:size(table_versions_campaign,1)
    if strcmp(table_versions_campaign.('product')(d),'office')
        sorted = sort_nat([table_versions_campaign.('min_version')(d) '2016-*']);
            if strcmp(sorted(end),'2016-*')
                sorted = sort_nat([table_versions_campaign.('max_version')(d) '2016-*']);
                if strcmp(sorted(1),'2016-*')
                    array_true = [array_true;1];
                else
                   array_true = [array_true;0]; 
                end
            else
                array_true = [array_true;0]; 
            end
    else
        %add it, it is not office so we need to maintain the campaign
        array_true = [array_true;1];
    end
end
array_true = logical(array_true);
table_versions_campaign_reduced = table_versions_campaign(array_true,:);

my_campaigns = unique(table_versions_campaign_reduced.('campaign'));

%counters of the number of unique campaigns that have success on the
%specific strategy
counter_vulnerable_strategy_on_the_edge = 0;
counter_vulnerable_strategy_autoupdate = 0;
counter_vulnerable_strategy_reactive = 0;
counter_vulnerable_strategy_informed_reactive = 0;
counter_vulnerable_strategy_reactive_on_advisory = 0;
counter_vulnerable_strategy_informed_reactive_on_advisory = 0;

set_camp_on_the_edge = [];
set_camp_autoupdate = [];
set_camp_reactive = [];
set_camp_informed_reactive = [];
set_camp_reactive_on_advisory = [];
set_camp_informed_reactive_on_advisory = [];

%compute the number of instant of times (months) in which you are
%compromisable for each strategy for each campaign
exposure_months_on_the_edge = [];
exposure_months_autoupdate = [];
exposure_months_reactive = [];
exposure_months_informed_reactive = [];
exposure_months_reactive_on_advisory = [];
exposure_months_informed_reactive_on_advisory = [];


%create a vector that identify in the i-th position a campaign to
%compare pair-wise performance of different strategies against same
%campaign. Add one if campaign successful, else 0
vect_campaigns_on_the_edge = [];
vect_campaigns_autoupdate = [];
vect_campaigns_reactive = [];
vect_campaigns_informed_reactive = [];
vect_campaigns_reactive_on_advisory = [];
vect_campaigns_informed_reactive_on_advisory = [];

for i=1:length(my_campaigns)
    %now get the list of vulnerable version for the campaign
    list_versions = products_vulns_versions.('version')(strcmp(products_vulns_versions.('campaign'),my_campaigns(i)));
    list_updates = products_vulns_versions.('update')(strcmp(products_vulns_versions.('campaign'),my_campaigns(i)));
    list_product = products_vulns_versions.('product')(strcmp(products_vulns_versions.('campaign'),my_campaigns(i)));
    list_vulnerable = unique(strcat(list_product,'-',list_versions,'-',list_updates));

    %intersect with the available versions, so that if there is not the
    %version in our collected timeline we ignore it
    list_vulnerable = intersect(table_strategy_on_the_edge.Properties.RowNames,list_vulnerable);

    %unfortunately for office this will NEVER work as we do not have KB in
    %products_vulns_versions and thus will only match the office-2016-* base case, thus let's see if office is an affected
    %product for the campaign
    if ~isempty(find(strcmp(strcat(list_product,'-',list_versions),'office-2016')))
       added_list = [];
       %get the CVE targeted for the office product so that we can have the
       %KB
       %filter by office
       products_vulns_versions_office = products_vulns_versions(strcmp(products_vulns_versions.('product'),'office'),:);
       my_cves = unique(products_vulns_versions_office.('vulnerability')(strcmp(products_vulns_versions_office.('campaign'),my_campaigns(i))));
       for b=1:length(my_cves)
          %we could have multiple CVEs exploited within a given campaign,
          %of which some can not target e.g. office 2016 but a previous
          %version thus let's skip these
          if max(str2double(products_vulns_versions_office.('version')(strcmp(products_vulns_versions_office.('vulnerability'),my_cves(b)))))<2016
            continue
          end
          %get KBs for the CVE
          kb_indexes = find(strcmp(office2016_versions.('advisory'),my_cves(b)));
          %we could have multiple KB, we then take only the most recent
          %one BY RELEASE DATE BECAUSE KB numbering is not linked to more
          %recent!!!!
          if length(kb_indexes)>1
                tmp_kb_indexes = table(kb_indexes,office2016_versions.('release_date')(kb_indexes));
                kb_index = tmp_kb_indexes{end,1};
          else
                kb_index = kb_indexes;
          end
          %extract the kb names FROM THE office2016_versions because it
          %is different from the product_specific_versions file
          kbs = strcat(office2016_versions.('version')(kb_index),'-',office2016_versions.('update')(kb_index));
          %now extract only the most recent KBs
          kbs = sort_nat(kbs);
          my_version = kbs(end);
          added_list = [added_list; strcat('office','-',my_version)];
       end
       list_vulnerable = [list_vulnerable;added_list];
    end

    %get date campaign (exploited_date), need unique because some CVE
    %affect more products and thus you have multiple entries
    exploited_date = unique(table_versions_campaign.('exploited_date')(strcmp(table_versions_campaign.('campaign'),my_campaigns(i))));
    %count the campaign in the timeline
    timeline_exploitations = timeline_exploitations + double(timeline>=exploited_date);

    %matrix for the specific campaign
    tmp_matrix_campaign = zeros(size(table_strategy_on_the_edge,1),length(timeline));
    for j=1:length(list_vulnerable)
        index = find(strcmp(table_strategy_on_the_edge.Properties.RowNames,list_vulnerable(j)));
        if contains(list_vulnerable(j),'office')
            %here all the KB BEFORE (as a temporal order) that one are vulnerable
            %get indexes for all OFFICE kb
            total_indexes_office = find(contains(table_strategy_on_the_edge.Properties.RowNames,'office'));
            affected_indexes = total_indexes_office(total_indexes_office<index);
            for m=1:length(affected_indexes)
                %the index represent the row i.e. the version affected, fill
                %with 1 from the exploited date.
                %we overwrite the values becase here we just want one if there is a
                %campaign affecting the version, not counting twice a campaign
                %affecting the version multiple time (due to e.g. multiple CVE
                %exploited)
                tmp_matrix_campaign(affected_indexes(m),:) = double(timeline>=exploited_date);
            end
        else
            %the index represent the row i.e. the version affected, fill
            %with 1 from the exploited date.
            %we overwrite the values becase here we just want one if there is a
            %campaign affecting the version, not counting twice a campaign
            %affecting the version multiple time (due to e.g. multiple CVE
            %exploited)
            tmp_matrix_campaign(index,:) = double(timeline>=exploited_date);
        end
    end

    %compute if the campaign compromises one of the strategies, we use 
    vulnerabilities_strategy_on_the_edge = table2array(table_strategy_on_the_edge).*tmp_matrix_campaign;
    vulnerabilities_strategy_autoupdate = table2array(table_strategy_autoupdate).*tmp_matrix_campaign;
    vulnerabilities_strategy_reactive = table2array(table_strategy_reactive).*tmp_matrix_campaign;
    vulnerabilities_strategy_informed_reactive = table2array(table_strategy_informed_reactive).*tmp_matrix_campaign;
    vulnerabilities_strategy_reactive_on_advisory = table2array(table_strategy_reactive_on_advisory).*tmp_matrix_campaign;
    vulnerabilities_strategy_informed_reactive_on_advisory = table2array(table_strategy_informed_reactive_on_advisory).*tmp_matrix_campaign;

    %now the previous table shows for which versions I am vulnerable, lets sum
    %up the rows (i.e. sum all the values in a columns) to get a single value
    %for which the company is vulnerable at time t for the specific
    %strategy
    %normalize to 1 because sum up the row can generate greater value if a
    %campaign affects more product, or in the case of a pessimistic
    %scenario the same product but two time in the same month
    vulns_strategy_on_the_edge = sum(vulnerabilities_strategy_on_the_edge,1);
    vulns_strategy_autoupdate = sum(vulnerabilities_strategy_autoupdate,1);
    vulns_strategy_reactive = sum(vulnerabilities_strategy_reactive,1);
    vulns_strategy_informed_reactive = sum(vulnerabilities_strategy_informed_reactive,1);
    vulns_strategy_reactive_on_advisory = sum(vulnerabilities_strategy_reactive_on_advisory,1);
    vulns_strategy_informed_reactive_on_advisory = sum(vulnerabilities_strategy_informed_reactive_on_advisory,1);


    vulns_strategy_on_the_edge(vulns_strategy_on_the_edge>1)=1;
    vulns_strategy_autoupdate(vulns_strategy_autoupdate>1)=1;
    vulns_strategy_reactive(vulns_strategy_reactive>1)=1;
    vulns_strategy_informed_reactive(vulns_strategy_informed_reactive>1)=1;
    vulns_strategy_reactive_on_advisory(vulns_strategy_reactive_on_advisory>1)=1;
    vulns_strategy_informed_reactive_on_advisory(vulns_strategy_informed_reactive_on_advisory>1)=1;

    %count if the campaign had success, we do not want to count it multiple
    %time if it succeed in multiple instant of time, so if there is at
    %least a 1 in the vector --> compromised
    if sum(vulns_strategy_on_the_edge)>0
        counter_vulnerable_strategy_on_the_edge = counter_vulnerable_strategy_on_the_edge + 1;
        set_camp_on_the_edge = [set_camp_on_the_edge ;my_campaigns(i)];
        vect_campaigns_on_the_edge = [vect_campaigns_on_the_edge;1];
    else
        vect_campaigns_on_the_edge = [vect_campaigns_on_the_edge;0];
    end
    
    if sum(vulns_strategy_autoupdate)>0
        counter_vulnerable_strategy_autoupdate = counter_vulnerable_strategy_autoupdate + 1; 
        set_camp_autoupdate = [set_camp_autoupdate ;my_campaigns(i)];
        vect_campaigns_autoupdate = [vect_campaigns_autoupdate;1];
    else
        vect_campaigns_autoupdate = [vect_campaigns_autoupdate;0];
    end
    
    if sum(vulns_strategy_reactive)>0
        counter_vulnerable_strategy_reactive = counter_vulnerable_strategy_reactive + 1;
        set_camp_reactive = [set_camp_reactive ;my_campaigns(i)];
        vect_campaigns_reactive = [vect_campaigns_reactive;1];
    else
        vect_campaigns_reactive = [vect_campaigns_reactive;0];
    end
    
    if sum(vulns_strategy_informed_reactive)>0
        counter_vulnerable_strategy_informed_reactive = counter_vulnerable_strategy_informed_reactive + 1;
        set_camp_informed_reactive = [set_camp_informed_reactive ;my_campaigns(i)];
        vect_campaigns_informed_reactive = [vect_campaigns_informed_reactive;1];
    else
        vect_campaigns_informed_reactive = [vect_campaigns_informed_reactive;0];
    end

    if sum(vulns_strategy_reactive_on_advisory)>0
        counter_vulnerable_strategy_reactive_on_advisory = counter_vulnerable_strategy_reactive_on_advisory + 1;
        set_camp_reactive_on_advisory = [set_camp_reactive_on_advisory ;my_campaigns(i)];
        vect_campaigns_reactive_on_advisory = [vect_campaigns_reactive_on_advisory;1];
    else
        vect_campaigns_reactive_on_advisory = [vect_campaigns_reactive_on_advisory;0];
    end
    
    if sum(vulns_strategy_informed_reactive_on_advisory)>0
        counter_vulnerable_strategy_informed_reactive_on_advisory = counter_vulnerable_strategy_informed_reactive_on_advisory + 1;
        set_camp_informed_reactive_on_advisory = [set_camp_informed_reactive_on_advisory ;my_campaigns(i)];
        vect_campaigns_informed_reactive_on_advisory = [vect_campaigns_informed_reactive_on_advisory;1];
    else
        vect_campaigns_informed_reactive_on_advisory = [vect_campaigns_informed_reactive_on_advisory;0];
    end
    
    %compute exposure in months for each campaign
    exposure_months_on_the_edge = [exposure_months_on_the_edge; length(find(vulns_strategy_on_the_edge))];
    exposure_months_autoupdate = [exposure_months_autoupdate; length(find(vulns_strategy_autoupdate))];
    exposure_months_reactive = [exposure_months_reactive; length(find(vulns_strategy_reactive))];
    exposure_months_informed_reactive = [exposure_months_informed_reactive; length(find(vulns_strategy_informed_reactive))];
    exposure_months_reactive_on_advisory = [exposure_months_reactive_on_advisory; length(find(vulns_strategy_reactive_on_advisory))];
    exposure_months_informed_reactive_on_advisory = [exposure_months_informed_reactive_on_advisory; length(find(vulns_strategy_informed_reactive_on_advisory))];
    
    %add to the total ones that count the campaigns each strategy is
    %vulnerable to at each instant of time
    tot_vulns_strategy_on_the_edge = tot_vulns_strategy_on_the_edge + vulns_strategy_on_the_edge;
    tot_vulns_strategy_autoupdate = tot_vulns_strategy_autoupdate + vulns_strategy_autoupdate;
    tot_vulns_strategy_reactive = tot_vulns_strategy_reactive + vulns_strategy_reactive;
    tot_vulns_strategy_informed_reactive = tot_vulns_strategy_informed_reactive + vulns_strategy_informed_reactive;
    tot_vulns_strategy_reactive_on_advisory = tot_vulns_strategy_reactive_on_advisory + vulns_strategy_reactive_on_advisory;
    tot_vulns_strategy_informed_reactive_on_advisory = tot_vulns_strategy_informed_reactive_on_advisory + vulns_strategy_informed_reactive_on_advisory;

    %add to a matrix that contains all the campaigns, this is useful to get
    %the general idea
    matrix_campaigns = matrix_campaigns + tmp_matrix_campaign;
end


set_camp_on_the_edge = unique(set_camp_on_the_edge);
set_camp_autoupdate = unique(set_camp_autoupdate);
set_camp_reactive = unique(set_camp_reactive);
set_camp_informed_reactive = unique(set_camp_informed_reactive);
set_camp_reactive_on_advisory = unique(set_camp_reactive_on_advisory);
set_camp_informed_reactive_on_advisory = unique(set_camp_informed_reactive_on_advisory);

fprintf("################\n")
fprintf("AVG Exposure on the edge:%d\n",mean(exposure_months_on_the_edge));
fprintf("AVG Exposure autoupdate:%d\n",mean(exposure_months_autoupdate));
fprintf("AVG Exposure reactive:%d\n",mean(exposure_months_reactive));
fprintf("AVG Exposure informed reactive:%d\n",mean(exposure_months_informed_reactive));
fprintf("AVG Exposure reactive on advisory:%d\n",mean(exposure_months_reactive_on_advisory));
fprintf("AVG Exposure informed reactive on advisory:%d\n",mean(exposure_months_informed_reactive_on_advisory));
fprintf("################\n")

%create table for exploit timeline over versions
table_exploits = array2table(matrix_campaigns);
table_exploits.Properties.RowNames = table_strategy_on_the_edge.Properties.RowNames;

%add column name
table_strategy_on_the_edge.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));
table_strategy_autoupdate.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));
table_strategy_reactive.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));
table_strategy_informed_reactive.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));
table_strategy_reactive_on_advisory.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));
table_strategy_informed_reactive_on_advisory.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));

table_exploits.Properties.VariableNames = matlab.lang.makeValidName(cellstr(timeline));

%now compute the probability to be compromise at a certain given time. this
%is computed as p(C|A)= (# of campaigns a company is vulnerable at that
%instant of time)/(tot # of campaigns at that instant of time)

%divide by the total number of attacks at each instant of time, we cannot
%use the table_exploit because if we sum the rows we could potentially
%count an attack that affects two different products as two different
%attacks, lets use the ./timeline_exploitations instead
prob_compromise_strategy_on_the_edge = tot_vulns_strategy_on_the_edge./timeline_exploitations;
prob_compromise_strategy_autoupdate = tot_vulns_strategy_autoupdate./timeline_exploitations;
prob_compromise_strategy_reactive = tot_vulns_strategy_reactive./timeline_exploitations;
prob_compromise_strategy_informed_reactive = tot_vulns_strategy_informed_reactive./timeline_exploitations;
prob_compromise_strategy_reactive_on_advisory = tot_vulns_strategy_reactive_on_advisory./timeline_exploitations;
prob_compromise_strategy_informed_reactive_on_advisory = tot_vulns_strategy_informed_reactive_on_advisory./timeline_exploitations;

%count the number of times you updates the software in the different
%strategies, this is the cost you have

%get the number of rows that are all zeros, these are the versions we did
%not install
n_not_installed_on_the_edge = length(find(all(table2array(table_strategy_on_the_edge)==0,2)));
n_not_installed_autoupdate = length(find(all(table2array(table_strategy_autoupdate)==0,2)));
n_not_installed_reactive = length(find(all(table2array(table_strategy_reactive)==0,2)));
n_not_installed_informed_reactive = length(find(all(table2array(table_strategy_informed_reactive)==0,2)));
n_not_installed_reactive_on_advisory = length(find(all(table2array(table_strategy_reactive_on_advisory)==0,2)));
n_not_installed_informed_reactive_on_advisory = length(find(all(table2array(table_strategy_informed_reactive_on_advisory)==0,2)));

%tot number of version available, same for all the tables
available_versions = size(table_strategy_on_the_edge,1);

n_installed_on_the_edge = available_versions - n_not_installed_on_the_edge;
n_installed_autoupdate = available_versions - n_not_installed_autoupdate;
n_installed_reactive = available_versions - n_not_installed_reactive;
n_installed_informed_reactive = available_versions - n_not_installed_informed_reactive;
n_installed_reactive_on_advisory = available_versions - n_not_installed_reactive_on_advisory;
n_installed_informed_reactive_on_advisory = available_versions - n_not_installed_informed_reactive_on_advisory;
fprintf("Number of updates for On the Edge strategy: %d\n",n_installed_on_the_edge);
fprintf("Number of updates for Autoupdate strategy: %d\n",n_installed_autoupdate);
fprintf("Number of updates for Reactive strategy: %d\n",n_installed_reactive);
fprintf("Number of updates for Informed Reactive strategy: %d\n",n_installed_informed_reactive);
fprintf("Number of updates for Reactive strategy on advisory: %d\n",n_installed_reactive_on_advisory);
fprintf("Number of updates for Informed Reactive strategy on advisory: %d\n",n_installed_informed_reactive_on_advisory);

p_on_the_edge_constant = sum(tot_vulns_strategy_on_the_edge)/sum(timeline_exploitations);
p_autoupdate_constant = sum(tot_vulns_strategy_autoupdate)/sum(timeline_exploitations);
p_reactive_constant = sum(tot_vulns_strategy_reactive)/sum(timeline_exploitations);
p_informed_reactive_constant = sum(tot_vulns_strategy_informed_reactive)/sum(timeline_exploitations);
p_reactive_constant_on_advisory = sum(tot_vulns_strategy_reactive_on_advisory)/sum(timeline_exploitations);
p_informed_reactive_constant_on_advisory = sum(tot_vulns_strategy_informed_reactive_on_advisory)/sum(timeline_exploitations);

%probability on unique campaigns
p_on_the_edge_constant = counter_vulnerable_strategy_on_the_edge/timeline_exploitations(end);
p_autoupdate_constant = counter_vulnerable_strategy_autoupdate/timeline_exploitations(end);
p_reactive_constant = counter_vulnerable_strategy_reactive/timeline_exploitations(end);
p_informed_reactive_constant = counter_vulnerable_strategy_informed_reactive/timeline_exploitations(end);
p_reactive_constant_on_advisory = counter_vulnerable_strategy_reactive_on_advisory/timeline_exploitations(end);
p_informed_reactive_constant_on_advisory = counter_vulnerable_strategy_informed_reactive_on_advisory/timeline_exploitations(end);

fprintf("#########################\n");
fprintf("Constant life of campaigns\n");
fprintf("P(C|A) for On the Edge strategy: %d\n",p_on_the_edge_constant);
fprintf("P(C|A) for Autoupdate strategy: %d\n",p_autoupdate_constant);
fprintf("P(C|A) for Reactive strategy: %d\n",p_reactive_constant);
fprintf("P(C|A) for Informed Reactive strategy: %d\n",p_informed_reactive_constant);
fprintf("P(C|A) for Reactive strategy on advisory: %d\n",p_reactive_constant_on_advisory);
fprintf("P(C|A) for Informed Reactive strategy on advisory: %d\n",p_informed_reactive_constant_on_advisory);

% compute the odds ratio between the proactive strategy and the other
% strategies
odds_on_the_edge_constant = p_on_the_edge_constant/(1-p_on_the_edge_constant);
odds_autoupdate_constant = p_autoupdate_constant/(1-p_autoupdate_constant);
odds_reactive_constant = p_reactive_constant/(1-p_reactive_constant);
odds_informed_reactive_constant = p_informed_reactive_constant/(1-p_informed_reactive_constant);
odds_reactive_constant_on_advisory = p_reactive_constant_on_advisory/(1-p_reactive_constant_on_advisory);
odds_informed_reactive_constant_on_advisory = p_informed_reactive_constant_on_advisory/(1-p_informed_reactive_constant_on_advisory);

odds_ratio_S1_S2_constant = odds_autoupdate_constant/odds_on_the_edge_constant;
odds_ratio_S1_S3_constant = odds_reactive_constant/odds_on_the_edge_constant;
odds_ratio_S1_S4_constant = odds_informed_reactive_constant/odds_on_the_edge_constant;
odds_ratio_S1_S5_constant = odds_reactive_constant_on_advisory/odds_on_the_edge_constant;
odds_ratio_S1_S6_constant = odds_informed_reactive_constant_on_advisory/odds_on_the_edge_constant;

fprintf("############################\n");
fprintf("Odds ratio constant campaigns\n");
fprintf("Autoupdate/On the Edge: %d\n",odds_ratio_S1_S2_constant);
fprintf("Reactive/On the Edge: %d\n",odds_ratio_S1_S3_constant);
fprintf("Informed Reactive/On the Edge: %d\n",odds_ratio_S1_S4_constant);
fprintf("Reactive on Advisory/On the Edge: %d\n",odds_ratio_S1_S5_constant);
fprintf("Informed Reactive on Advisory/On the Edge: %d\n",odds_ratio_S1_S6_constant);

table_final_results = [table_final_results;table(repmat(r,6,1),["edge";"autoupdate";"reactive";"informed_reactive";"reactive_on_advisory";"informed_reactive_on_advisory"],[n_installed_on_the_edge;n_installed_autoupdate;n_installed_reactive;n_installed_informed_reactive;n_installed_reactive_on_advisory;n_installed_informed_reactive_on_advisory], ...
    [p_on_the_edge_constant*100.0;p_autoupdate_constant*100.0;p_reactive_constant*100.0;p_informed_reactive_constant*100.0;p_reactive_constant_on_advisory*100.0;p_informed_reactive_constant_on_advisory*100.0], ...
    [1;odds_ratio_S1_S2_constant;odds_ratio_S1_S3_constant;odds_ratio_S1_S4_constant;odds_ratio_S1_S5_constant;odds_ratio_S1_S6_constant],'VariableNames',{'simulation','strategy','n_updates','probability','odds'})];
end

%% AGRESTI-COULL CI
%the simulation can be seen as a binomial distribution (x of successful
%campaign over n trials). We use the Agresti-coull to get a CI
[CI_on_the_edge_min,CI_on_the_edge_max] = agresti_coull(counter_vulnerable_strategy_on_the_edge,timeline_exploitations(end));
[CI_autoupdate_min,CI_autoupdate_max] = agresti_coull(counter_vulnerable_strategy_autoupdate,timeline_exploitations(end));
[CI_reactive_min,CI_reactive_max] = agresti_coull(counter_vulnerable_strategy_reactive,timeline_exploitations(end));
[CI_informed_reactive_min,CI_informed_reactive_max] = agresti_coull(counter_vulnerable_strategy_informed_reactive,timeline_exploitations(end));
[CI_reactive_on_advisory_min,CI_reactive_on_advisory_max] = agresti_coull(counter_vulnerable_strategy_reactive_on_advisory,timeline_exploitations(end));
[CI_informed_reactive_on_advisory_min,CI_informed_reactive_on_advisory_max] = agresti_coull(counter_vulnerable_strategy_informed_reactive_on_advisory,timeline_exploitations(end));


save CI_on_the_edge_min_1_true.mat CI_on_the_edge_min
save CI_on_the_edge_max_1_true.mat CI_on_the_edge_max

save CI_autoupdate_min_1_true.mat CI_autoupdate_min
save CI_autoupdate_max_1_true.mat CI_autoupdate_max

save CI_reactive_min_1_true.mat CI_reactive_min
save CI_reactive_max_1_true.mat CI_reactive_max

save CI_informed_reactive_min_1_true.mat CI_informed_reactive_min
save CI_informed_reactive_max_1_true.mat CI_informed_reactive_max

save CI_reactive_on_advisory_min_1_true.mat CI_reactive_on_advisory_min
save CI_reactive_on_advisory_max_1_true.mat CI_reactive_on_advisory_max

save CI_informed_reactive_on_advisory_min_1_true.mat CI_informed_reactive_on_advisory_min
save CI_informed_reactive_on_advisory_max_1_true.mat CI_informed_reactive_on_advisory_max

figure
x = [CI_on_the_edge_min,CI_on_the_edge_max,nan,CI_autoupdate_min,CI_autoupdate_max,nan,...
    CI_reactive_min,CI_reactive_max,nan,CI_informed_reactive_min,CI_informed_reactive_max,nan,...
    CI_reactive_on_advisory_min,CI_reactive_on_advisory_max,nan,CI_informed_reactive_on_advisory_min,CI_informed_reactive_on_advisory_max];
y = [1,1,nan,1.1,1.1,nan,1.2,1.2,nan,1.3,1.3,nan,1.4,1.4,nan,1.5,1.5];
x0=10;
y0=10;
width=550;
height=300;
set(gcf,'position',[x0,y0,width,height])
plot(x,y,'-')
hold on
scatter(x, y,'filled','o');
xlim([0.0,1])
ylim([0.9,1.6])
yticks([1:0.1:1.5])
xticks([0:0.1:1])
xticklabels({0,10,20,30,40,50,60,70,80,90,100})
a = get(gca,'YTickLabel');  
yticklabels({'Immediate','Planned','Reactive','Informed Reactive','Reactive on Advisory','Informed Reactive on Advisory'})
xlabel("Confidence Interval (%)")

print('-depsc',strcat('CI-agresti_months_',string(avg_patch_90_months),'.eps'))


%% CI SIGN TEST between strategies

%perform pair-wise comparison of performance for each single campaign, if
%campaigns agree (i.e. both successfull or both unsuccessful --> 1, else 0)

pr_immediate_vs_autoupdate = ~xor(vect_campaigns_on_the_edge,vect_campaigns_autoupdate);
pr_autoupdate_vs_reactive = ~xor(vect_campaigns_autoupdate,vect_campaigns_reactive);
pr_autoupdate_vs_informed_reactive = ~xor(vect_campaigns_autoupdate,vect_campaigns_informed_reactive);
pr_reactive_vs_informed_reactive = ~xor(vect_campaigns_reactive,vect_campaigns_informed_reactive);
pr_reactive_vs_reactive_on_advisory = ~xor(vect_campaigns_reactive,vect_campaigns_reactive_on_advisory);
pr_informed_reactive_vs_informed_reactive_on_advisory = ~xor(vect_campaigns_informed_reactive,vect_campaigns_informed_reactive_on_advisory);
fprintf("### CI COMPARISON ###\n")
[CI_on_the_edge_vs_autoupdate_min,CI_on_the_edge_vs_autoupdate_max] = agresti_coull(sum(pr_immediate_vs_autoupdate),length(pr_immediate_vs_autoupdate));
fprintf("CI On the Edge-Autoupdate: [%f,%f]\n",CI_on_the_edge_vs_autoupdate_min,CI_on_the_edge_vs_autoupdate_max);
[CI_autoupdate_vs_reactive_min,CI_autoupdate_vs_reactive_max] = agresti_coull(sum(pr_autoupdate_vs_reactive),length(pr_autoupdate_vs_reactive));
fprintf("CI Autoupdate-Reactive: [%f,%f]\n",CI_autoupdate_vs_reactive_min,CI_autoupdate_vs_reactive_max);
[CI_autoupdate_vs_informed_reactive_min,CI_autoupdate_vs_informed_reactive_max] = agresti_coull(sum(pr_autoupdate_vs_informed_reactive),length(pr_autoupdate_vs_informed_reactive));
fprintf("CI Autoupdate-Informed Reactive: [%f,%f]\n",CI_autoupdate_vs_informed_reactive_min,CI_autoupdate_vs_informed_reactive_max);
[CI_reactive_vs_informed_reactive_min,CI_reactive_vs_informed_reactive_max] = agresti_coull(sum(pr_reactive_vs_informed_reactive),length(pr_reactive_vs_informed_reactive));
fprintf("CI Reactive-Informed Reactive: [%f,%f]\n",CI_reactive_vs_informed_reactive_min,CI_reactive_vs_informed_reactive_max);
[CI_reactive_vs_reactive_on_advisory_min,CI_reactive_vs_reactive_on_advisory_max] = agresti_coull(sum(pr_reactive_vs_reactive_on_advisory),length(pr_reactive_vs_reactive_on_advisory));
fprintf("CI Reactive-Reactive on Advisory: [%f,%f]\n",CI_reactive_vs_reactive_on_advisory_min,CI_reactive_vs_reactive_on_advisory_max);
[CI_informed_reactive_vs_informed_reactive_on_advisory_min,CI_informed_reactive_vs_informed_reactive_on_advisory_max] = agresti_coull(sum(pr_informed_reactive_vs_informed_reactive_on_advisory),length(pr_informed_reactive_vs_informed_reactive_on_advisory));
fprintf("CI Informed Reactive-Informed Reactive on Advisory: [%f,%f]\n",CI_informed_reactive_vs_informed_reactive_on_advisory_min,CI_informed_reactive_vs_informed_reactive_on_advisory_max);


%% SURVIVAL FOCUS ON SPECIFIC PRODUCTS
%plot survival test of *FIRST* exploitation of CVEs by consider all the
%products and the simulated ones
%lets compute the survival also for the 5 products of interest
apts_vulnerabilities_unique_subset = table();
%the unique_cves contains only the CVEs affecting our 5 products
for i=1:length(unique_cves)
    a = first_occurence_vulnerability(strcmp(first_occurence_vulnerability.('CVE'),unique_cves(i)),:);
    apts_vulnerabilities_unique_subset = [apts_vulnerabilities_unique_subset;a];
end
delta_time_NVD_subset = datenum(apts_vulnerabilities_unique_subset.('exploited_time')) - datenum(apts_vulnerabilities_unique_subset.('published_time'));
delta_time_NVD_months_subset = round(delta_time_NVD_subset/30);

%plot survival test 
figure
hold on
set(gca,'FontSize',12)
grid on
positive_delta_time = delta_time_NVD_months(delta_time_NVD_months>=0);
%ecdf(positive_delta_time,'function','survivor');
ecdf(delta_time_NVD_months,'function','survivor');
ecdf(delta_time_NVD_months_subset,'function','survivor');
%title("Kaplan–Meier estimate of the survivor function")
legend('All products','Office,Flash,Reader,Air,JRE')
xlabel("Months from publication [months]")
ylabel("Cumulative prob. interest for exploitation")
xticks([-50:10:65]);
xlim([-50 65])
print -depsc survival-delta-CVE.eps