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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract between balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Dependency**: The vulnerability relies on the sender's balance being decremented before the recipient's balance is incremented, creating a window where contract state is inconsistent.
 * 
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transfer() to their malicious contract
 *    - During the external call, the malicious contract can call transfer() again
 *    - Since sender's balance was already decremented but recipient's balance not yet incremented, the second call sees stale state
 *    - This allows multiple withdrawals from the same initial balance
 * 
 * 3. **Persistent State Changes**: Each reentrant call permanently modifies the balances mapping, and these changes persist across transactions. The attacker can drain more tokens than they originally owned through accumulated state manipulation.
 * 
 * 4. **Realistic Implementation**: The notification mechanism is a common pattern in token contracts for informing recipients of incoming transfers, making this vulnerability realistic and subtle.
 * 
 * The vulnerability cannot be exploited in a single atomic transaction because it requires the recipient contract to make additional calls back to the transfer function, creating a sequence of state changes that accumulate across multiple internal transactions within the same external transaction call.
 */
pragma solidity ^0.4.16;

contract owned {
    address owner;
    function owned() public { owner = msg.sender; }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

interface ITransferNotification {
    function onTokenReceived(address _from, uint256 _value) external;
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

    function TokenArtFinity() public {
        balances[msg.sender] = totalSupply; 
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update sender's balance first
        balances[msg.sender] -= _value;
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            ITransferNotification(_to).onTokenReceived(msg.sender, _value);
        }
        
        // Update recipient's balance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferTokenWithGoods(address goodsWithdrawer, uint256 _value, uint32 goodsId, uint32 goodsNum) public onlyOwner returns (bool success) {
        
        require(balances[msg.sender] >= _value && balances[goodsWithdrawer] + _value > balances[goodsWithdrawer]);
        require(goodsWithdrawer != 0x0);
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
