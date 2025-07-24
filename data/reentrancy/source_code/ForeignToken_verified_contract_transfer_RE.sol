/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability allows malicious contracts to re-enter the transfer function multiple times, exploiting the fact that balances are only updated after the external call. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **First Transaction**: Initial transfer triggers external call to malicious contract, which can re-enter transfer function while original sender's balance is still intact
 * 2. **Subsequent Transactions**: Each re-entrant call can transfer the same tokens again since balances haven't been updated yet
 * 3. **State Accumulation**: The vulnerability becomes more severe as the malicious contract accumulates multiple transfers across different transactions
 * 
 * The vulnerability is stateful because:
 * - The malicious contract can set up state in transaction 1 to exploit in transaction 2+
 * - Each successful re-entrant call depletes the sender's balance progressively
 * - The exploit requires multiple function calls to drain significant funds
 * - The vulnerability persists across transaction boundaries due to improper state management
 * 
 * This injection maintains the ERC20 transfer functionality while creating a realistic vulnerability pattern seen in many production contracts that attempt to notify recipients of token transfers.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => uint256) public balances;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];
        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];
        
        if (sufficientFunds && !overflowed) {
            // Check if recipient is a contract and has accumulated multiple transfers
            uint256 size;
            assembly { size := extcodesize(_to) }
            bool isContract = size > 0;
            
            // External call to recipient before state updates (vulnerability injection)
            if (isContract) {
                // Call recipient's receive function - allows reentrancy
                bool callSuccess = _to.call.value(0)(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // suppress unused variable warning
                callSuccess;
            }
            
            // State updates happen after external call - vulnerable to reentrancy
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

contract ZukerEthereumToken {
    address owner = msg.sender;

    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;

    function name() constant returns (string) { return "ZUKER COIN"; }
    function symbol() constant returns (string) { return "ZUKKK"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

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
            
            Transfer(msg.sender, _to, _value);
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

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            allowed[_from][msg.sender] -= _value;
            
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }
        
        allowed[msg.sender][_spender] = _value;
        
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

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

            bytes20 bonusHash = ripemd160(block.coinbase, block.number, block.timestamp);
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
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}
