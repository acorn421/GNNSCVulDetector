/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent allowance expiration mechanism that creates a stateful, multi-transaction vulnerability. The code adds logic to check if allowances have expired after 1 hour using block.timestamp, but declares the allowanceTimestamps mapping locally within the function instead of as a contract state variable. This creates a critical flaw where the timestamp data is never actually stored or retrieved between transactions, making the time-based validation completely ineffective. The vulnerability requires multiple transactions to exploit: first an approve() call to set allowance, then a transferFrom() call after timestamp manipulation. Miners can manipulate block.timestamp within the ~15 second tolerance to bypass the intended 1-hour expiration or cause unexpected allowance invalidation across multiple transactions.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract ZukerEthereumToken {
    address owner = msg.sender;

    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    mapping (address => mapping (address => uint256)) allowanceTimestamps;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;

    function name() constant returns (string) { return "ZUKER COIN"; }
    function symbol() constant returns (string) { return "ZUKKK"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            emit Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based allowance validation - allowances expire after 1 hour
        if (allowanceTimestamps[_from][msg.sender] != 0) {
            uint256 timeSinceApproval = block.timestamp - allowanceTimestamps[_from][msg.sender];
            if (timeSinceApproval > 3600) { // 1 hour = 3600 seconds
                allowed[_from][msg.sender] = 0;
                allowance = 0;
                sufficientAllowance = false;
            }
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            emit Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        allowanceTimestamps[msg.sender][_spender] = block.timestamp; // Needed for timestamp dependence
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { revert(); }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, totalBonusTokensIssued, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * 1000);

        if (msg.value >= 10 finney) {
            tokensIssued += totalContribution;

            bytes20 bonusHash = ripemd160(abi.encodePacked(block.coinbase, block.number, block.timestamp));
            if (bonusHash[0] == 0) {
                uint8 bonusMultiplier =
                    (((bonusHash[1] & 0x01) != 0) ? 1 : 0) + (((bonusHash[1] & 0x02) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x04) != 0) ? 1 : 0) + (((bonusHash[1] & 0x08) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x10) != 0) ? 1 : 0) + (((bonusHash[1] & 0x20) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x40) != 0) ? 1 : 0) + (((bonusHash[1] & 0x80) != 0) ? 1 : 0);
                
                uint256 bonusTokensIssued = (msg.value * 1000) * bonusMultiplier;
                tokensIssued += bonusTokensIssued;

                totalBonusTokensIssued += bonusTokensIssued;
            }
        }

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        emit Transfer(address(this), msg.sender, tokensIssued);
    }
}
