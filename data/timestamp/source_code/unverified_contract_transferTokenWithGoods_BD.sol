/*
 * ===== SmartInject Injection Details =====
 * Function      : transferTokenWithGoods
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based transfer restrictions for high-value transfers. The vulnerability uses block.timestamp in a flawed calculation that depends on accumulated state from previous transfers in goodsTransferArray. The lastTransferTime calculation is vulnerable to timestamp manipulation and creates a multi-transaction attack vector where:
 * 
 * 1. **Transaction 1**: Attacker performs initial transfers to populate goodsTransferArray
 * 2. **Transaction 2**: Attacker (as owner or through compromised owner) attempts high-value transfer
 * 3. **Transaction 3**: Miner manipulates block.timestamp to bypass the 24-hour cooling period
 * 
 * The vulnerability requires multiple transactions because the state accumulation in goodsTransferArray affects the timestamp calculation, and the exploit depends on the relationship between stored transfer history and current block.timestamp. The flawed logic calculates lastTransferTime based on array index position rather than actual timestamps, making it manipulable through strategic transaction timing and miner timestamp manipulation.
 */
pragma solidity ^0.4.16;

contract owned {
    constructor () public { owner = msg.sender; }
    address owner;

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

contract TokenArtFinity is owned {
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    string public name = "ArtFinity";    //token name
    uint8 public decimals = 5;              
    string public symbol = "AT";           
    uint256 public totalSupply = 100000000000000; 
    GoodsTransferInfo[] public goodsTransferArray;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    struct GoodsTransferInfo {
        address withDrawAddress;
        uint32 goodsId;
        uint32 goodsNum;
    }

    constructor () public {
        balances[msg.sender] = totalSupply; 
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferTokenWithGoods(address goodsWithdrawer, uint256 _value, uint32 goodsId, uint32 goodsNum) public onlyOwner returns (bool success) {
        
        require(balances[msg.sender] >= _value && balances[goodsWithdrawer] + _value > balances[goodsWithdrawer]);
        require(goodsWithdrawer != 0x0);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based transfer restrictions with accumulated state vulnerability
        uint256 currentTime = block.timestamp;
        
        // Check if this is a high-value transfer (> 1000 tokens)
        if (_value > 1000) {
            // For high-value transfers, check if enough time has passed since last transfer
            bool hasRecentTransfer = false;
            for (uint i = 0; i < goodsTransferArray.length; i++) {
                if (goodsTransferArray[i].withDrawAddress == goodsWithdrawer) {
                    // Vulnerable: Using block.timestamp without proper validation
                    // The lastTransferTime is calculated based on accumulated transfer count
                    uint256 lastTransferTime = currentTime - (i * 3600); // 1 hour per previous transfer
                    if (currentTime - lastTransferTime < 86400) { // 24 hours cooling period
                        hasRecentTransfer = true;
                        break;
                    }
                }
            }
            require(!hasRecentTransfer, "High-value transfer cooling period not met");
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[goodsWithdrawer] += _value;
        goodsTransferArray.push(GoodsTransferInfo(goodsWithdrawer, goodsId, goodsNum));
        emit Transfer(msg.sender, goodsWithdrawer, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {

        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value; 
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)   
    { 
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    
    function goodsTransferArrayLength() public constant returns(uint256 length) {
        return goodsTransferArray.length;
    }
}