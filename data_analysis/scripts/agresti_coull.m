function [outputArg1,outputArg2] = agresti_coull(n_success,n_trials)
digits(10)
%Agresti-Coull CI for 95% -> in R there's a function that does the job for
%you --> add4ci
p_mean = n_success/n_trials;

a = (1+4/n_trials);
b = (-2*p_mean - 4/n_trials);
c = p_mean^2;
%use vpa to get more digit and thus more precision
outputArg1 = (vpa(-b) - vpa(sqrt(b^2-4*a*c)))/vpa(2*a);
outputArg2 = (vpa(-b) + vpa(sqrt(b^2-4*a*c)))/vpa(2*a);
end

