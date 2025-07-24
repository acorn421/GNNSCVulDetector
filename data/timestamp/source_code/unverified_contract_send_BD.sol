/*
 * ===== SmartInject Injection Details =====
 * Function      : send
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
 * Introduced a stateful timestamp dependence vulnerability that uses both block.number and block.timestamp for tax calculations. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * 1. **Block-based promotional periods**: Tax rate is halved every 256 blocks during the first 64 blocks of each cycle, with state tracking via lastPromotionalBlock mapping.
 * 
 * 2. **Time-based trading bonuses**: Consecutive transfers within 5 minutes receive progressive tax reductions based on the time difference, tracked via lastTransferTime mapping.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Attacker monitors block numbers and initiates transfers during promotional periods (blocks % 256 < 64) to get 50% tax reduction
 * - **Transaction 2+**: Attacker performs rapid successive transfers within 5-minute windows to stack time-based bonuses on top of promotional rates
 * - **State Persistence**: The lastTransferTime and lastPromotionalBlock mappings maintain state between transactions, enabling progressive exploitation
 * 
 * **Why Multi-Transaction Required:**
 * - Single transaction cannot exploit both timing mechanisms simultaneously
 * - The time-based bonus requires a previous transaction to establish lastTransferTime baseline
 * - Maximum exploitation requires coordinating transfers across multiple block cycles and time windows
 * - Miners can manipulate block.timestamp across multiple blocks to optimize tax reductions over time
 * 
 * This creates a realistic vulnerability where timing manipulation across multiple transactions can significantly reduce transaction taxes through accumulated state-dependent calculations.
 */
pragma solidity ^0.4.8;

contract testingToken {
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public weiWantedOf;
    mapping (address => uint256) public tokensOfferedOf;
    mapping (address => bool) public tradeActive;
    // ===== FIX: Declare missing mappings for vulnerability code =====
    mapping (address => uint256) public lastPromotionalBlock;
    mapping (address => uint256) public lastTransferTime;
    // ===============================================================
    address public bank;
    uint256 public ethTaxRate = 10;
    uint256 public tokenTaxRate = 5;
    function testingToken() {
        bank = msg.sender;
        balanceOf[msg.sender] = 100000;
    }
    
    function send(address _to, uint256 _value) { //give tokens to someone
        if (balanceOf[msg.sender]<_value) throw;
        if (balanceOf[_to]+_value<balanceOf[_to]) throw;
        if (_value<0) throw;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based tax reduction mechanism - promotional periods every 256 blocks
        uint256 effectiveTaxRate = tokenTaxRate;
        uint256 blockCycle = block.number % 256;
        if (blockCycle < 64) {
            // Store the promotional tax state for consistency tracking
            lastPromotionalBlock[msg.sender] = block.number;
            effectiveTaxRate = tokenTaxRate / 2; // 50% tax reduction during promotional period
        }
        
        // Additional time-based bonus for frequent traders
        if (lastTransferTime[msg.sender] != 0 && (block.timestamp - lastTransferTime[msg.sender]) < 300) {
            // Bonus applies if transfer within 5 minutes of last transfer
            uint256 timeBonusReduction = (300 - (block.timestamp - lastTransferTime[msg.sender])) / 30;
            if (timeBonusReduction > effectiveTaxRate) {
                effectiveTaxRate = 0;
            } else {
                effectiveTaxRate -= timeBonusReduction;
            }
        }
        
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += (_value*(100-effectiveTaxRate))/100;
        balanceOf[bank] += (_value*effectiveTaxRate)/100;
        
        // Update timestamp for future time-based calculations
        lastTransferTime[msg.sender] = block.timestamp;
        
        //now check for rounding down which would result in permanent loss of coins
        if (((_value*effectiveTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function offerTrade(uint256 _weiWanted, uint256 _tokensOffered) { //offer the amt of ether you want and the amt of tokens youd give
        weiWantedOf[msg.sender] = _weiWanted;
        tokensOfferedOf[msg.sender] = _tokensOffered;
        tradeActive[msg.sender] = true;
    }
    function agreeToTrade(address _from) payable { //choose a trade to agree to and execute it
        if (!tradeActive[_from]) throw;
        if (weiWantedOf[_from]!=msg.value) throw;
        if (balanceOf[_from]<tokensOfferedOf[_from]) throw;
        if (!_from.send((msg.value*(100-ethTaxRate))/100)) throw;
        balanceOf[_from] -= tokensOfferedOf[_from];
        balanceOf[msg.sender] += (tokensOfferedOf[_from]*(100-tokenTaxRate))/100;
        balanceOf[bank] += (tokensOfferedOf[_from]*tokenTaxRate)/100;
        tradeActive[_from] = false;
        //now check for rounding down which would result in permanent loss of coins
        if (((tokensOfferedOf[_from]*tokenTaxRate*10)/100)%10 != 0) balanceOf[bank]+=1;
    }
    
    modifier bankOnly {
        if (msg.sender != bank) throw;
        _;
    }
    
    function setTaxes(uint256 _ethTaxRate, uint256 _tokenTaxRate) bankOnly { //the bank can change the tax rates
        ethTaxRate = _ethTaxRate;
        tokenTaxRate = _tokenTaxRate;
    }
    function extractWei(uint256 _wei) bankOnly { //withdraw money from the contract
        if (!msg.sender.send(_wei)) throw;
    }
    function transferOwnership(address _bank) bankOnly { //change owner
        bank = _bank;
    }
}