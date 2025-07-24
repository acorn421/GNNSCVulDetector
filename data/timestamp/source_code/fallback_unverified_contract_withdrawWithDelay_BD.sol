/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawWithDelay
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where miners can manipulate block timestamps to bypass withdrawal delays. The vulnerability is stateful and requires multiple transactions: first calling requestWithdrawal() to set the withdrawal request timestamp, then calling withdrawWithDelay() after the supposed delay period. However, miners can manipulate timestamps within a ~15 minute window, potentially allowing earlier withdrawals than intended. The vulnerability persists in contract state through the withdrawalRequests mapping until the withdrawal is completed.
 */
pragma solidity ^0.4.14;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}





contract DoneToken {
    
    address owner = msg.sender;
 
 
    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;

    uint256 public totalSupply = 0;

    uint256 constant September1 = 1504274400; //2 PM GMT 9/1/2017
    uint256 constant August25 = 1503669600; //2 PM GMT 8/25/2017
    uint256 constant testtime = 1502003216; //20 minutes


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping (address => uint256) public withdrawalRequests;
    mapping (address => uint256) public withdrawalAmounts;
    uint256 public withdrawalDelay = 7 days;
    
    function requestWithdrawal(uint256 _amount) returns (bool) {
        if (balances[msg.sender] < _amount) { throw; }
        if (_amount == 0) { return false; }
        
        withdrawalRequests[msg.sender] = block.timestamp;
        withdrawalAmounts[msg.sender] = _amount;
        
        return true;
    }
    
    function withdrawWithDelay() returns (bool) {
        if (withdrawalRequests[msg.sender] == 0) { throw; }
        
        // Vulnerable: Using block.timestamp for time-based logic
        // Miners can manipulate timestamp within ~15 minute window
        if (block.timestamp < withdrawalRequests[msg.sender] + withdrawalDelay) {
            throw;
        }
        
        uint256 amount = withdrawalAmounts[msg.sender];
        if (balances[msg.sender] < amount) { throw; }
        
        balances[msg.sender] -= amount;
        withdrawalRequests[msg.sender] = 0;
        withdrawalAmounts[msg.sender] = 0;
        
        msg.sender.transfer(amount);
        return true;
    }
    // === END FALLBACK INJECTION ===

    function name() constant returns (string) { return "Donation Efficiency Token"; }
    function symbol() constant returns (string) { return "DONE"; }
    function decimals() constant returns (uint8) { return 16; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        if(msg.data.length < (2 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if(msg.data.length < (3 * 32) + 4) { throw; }

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() {
        if (msg.sender != owner) { throw; }
        
        if (totalContribution > 1000000000000000000000) {throw;} //purchasing cannot be re-enabled
                                  
        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
    }

   
   
    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { throw; }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, bool) {
        return (totalContribution, totalSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;
        
        if (block.timestamp > August25){
        
        uint256 tokensIssued = (msg.value * 5);
        }
        else tokensIssued = (msg.value * 10);
        
        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}