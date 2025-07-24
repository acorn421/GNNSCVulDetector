/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleRewardRelease
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
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for time-sensitive operations. The vulnerability is stateful and multi-transaction: (1) First transaction calls scheduleRewardRelease() which sets a future release time based on 'now', (2) The state persists between transactions with _rewardScheduled flag and _rewardReleaseTime, (3) Second transaction calls executeScheduledReward() which checks if 'now >= _rewardReleaseTime'. Miners can manipulate timestamps within certain bounds to potentially release rewards earlier than intended, especially for short delay periods.
 */
pragma solidity  ^0.4.24;
contract AllYours {

    // uint128 private _totalEth = 0.2 ether;

    // uint128 private _winTotalEth = 0.15 ether;

    // uint128 private _platformTotalEth = 0.05 ether;

    // uint16 private _needTimes = 4;

    // uint128 private _oneceEth = 0.05 ether;

     // uint24 private _needTimes = 10;

   

    address private _platformAddress = 0xbE9C1088FEEB8B48A96Da0231062eA757D0a9613;

    uint private _totalEth = 0.05 ether;

 

    uint128 private _oneceEth = 0.01 ether;

    uint256 private _period = 1;

    address private _owner;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables must be declared at contract scope, not inside constructor
    uint256 private _rewardReleaseTime;
    address private _scheduledRewardRecipient;
    uint256 private _scheduledRewardAmount;
    bool private _rewardScheduled = false;
    // === END FALLBACK INJECTION ===

    constructor() public{
        _owner = msg.sender;
    }

    // mapping(address => uint16) private _playerOfNumber;

    mapping(uint24 => address) private _allPlayer;

    address[] private _allAddress;

    uint16 private _currentJoinPersonNumber;

    string private _historyJoin;

    event drawCallback(address winnerAddress,uint period,uint balance,uint time );

    function getCurrentJoinPersonNumber() view public returns(uint24) {
        return _currentJoinPersonNumber;
    }

    // function getAddressJoinPersonNumber() view public returns(uint24) {
    // return _playerOfNumber[msg.sender];
    // }

    function getHistory() view public returns(string) {
        return _historyJoin;
    }

    function getPeriod() view public returns(uint256) {
        return _period;
    }
    function getCurrentBalance() view public returns(uint256) {
        return address(this).balance;
    }

    function draw() internal view returns (uint24) {
        bytes32 hash = keccak256(abi.encodePacked(block.number));
        uint256 random = 0;
        for(uint i=hash.length-8;i<hash.length;i++) {
            random += uint256(hash[i])*(10**(hash.length-i));
        }
        random += now;
         bytes memory hashAddress=toBytes(_allAddress[0]); 
         for(uint j=0;j<8;j++) {
            random += uint(hashAddress[j])*(10**(8-j));
        }
        uint24 index = uint24(random % _allAddress.length);
        return index;
    }

    // 销毁当前合约
    function kill() public payable {
        if (_owner == msg.sender) {
             _platformAddress.transfer(address(this).balance);
            selfdestruct(_owner);
        }
    }

    function() public payable {
        require(msg.value >= _oneceEth);
        // _playerOfNumber[msg.sender] += 1;
        uint len = msg.value/_oneceEth;
        for(uint i=0;i<len;i++) {
            _allPlayer[_currentJoinPersonNumber ++] = msg.sender;
            _allAddress.push(msg.sender);
        }
        _historyJoin = strConcat(_historyJoin,"&",uint2str(now),"|",addressToString(msg.sender)) ;
        if(address(this).balance >= _totalEth) {
            uint24 index = draw();
            address drawAddress = _allPlayer[index];
            uint256 b = address(this).balance;
            uint256 pay = b*70/100;
            drawAddress.transfer(pay);
            _platformAddress.transfer(b*30/100);
            emit drawCallback(drawAddress,_period,pay,now);
            _period ++;
          clear();
        }
    }
    
    function clear() internal {
         for(uint16 i=0;i<_allAddress.length;i++) {
                // delete _playerOfNumber[_allAddress[i]];
                delete _allPlayer[i];
            }
           _currentJoinPersonNumber = 0;
          _historyJoin = "";
           delete _allAddress;
    }

    function toBytes(address x) internal pure returns (bytes b) {
         b = new bytes(20);
         for (uint i = 0; i < 20; i++)
                b[i] = byte(uint8(uint(x) / (2**(8*(19 - i)))));
    }

   function addressToString(address _addr) internal pure returns (string) {
               bytes32 value = bytes32(uint256(_addr));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = '0';
        str[1] = 'x';
        for (uint i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint(value[i + 12] >> 4)];
            str[3+i*2] = alphabet[uint(value[i + 12] & 0x0f)];
        }
        return string(str);
    }
    
    function uint2str(uint256 i) internal pure returns (string){
        if (i == 0) return "0";
        uint j = i;
        uint len;
        while (j != 0){
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (i != 0){
            bstr[k--] = byte(48 + i % 10);
            i /= 10;
        }
        return string(bstr);
    }

     function strConcat(string _a, string _b, string _c, string _d, string _e) internal pure returns (string) {
        bytes memory _ba = bytes(_a);
        bytes memory _bb = bytes(_b);
        bytes memory _bc = bytes(_c);
        bytes memory _bd = bytes(_d);
        bytes memory _be = bytes(_e);
        string memory abcde = new string(_ba.length + _bb.length + _bc.length + _bd.length + _be.length);
        bytes memory babcde = bytes(abcde);
        uint k = 0;
        for (uint i = 0; i < _ba.length; i++) babcde[k++] = _ba[i];
        for (i = 0; i < _bb.length; i++) babcde[k++] = _bb[i];
        for (i = 0; i < _bc.length; i++) babcde[k++] = _bc[i];
        for (i = 0; i < _bd.length; i++) babcde[k++] = _bd[i];
        for (i = 0; i < _be.length; i++) babcde[k++] = _be[i];
        return string(babcde);
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    function scheduleRewardRelease(address recipient, uint256 amount, uint256 delayMinutes) public {
        require(msg.sender == _owner, "Only owner can schedule rewards");
        require(amount <= address(this).balance, "Insufficient balance");
        require(!_rewardScheduled, "Reward already scheduled");
        _rewardReleaseTime = now + (delayMinutes * 60);
        _scheduledRewardRecipient = recipient;
        _scheduledRewardAmount = amount;
        _rewardScheduled = true;
    }
    function executeScheduledReward() public {
        require(_rewardScheduled, "No reward scheduled");
        require(now >= _rewardReleaseTime, "Reward not ready for release");
        address recipient = _scheduledRewardRecipient;
        uint256 amount = _scheduledRewardAmount;
        _rewardScheduled = false;
        _scheduledRewardRecipient = address(0);
        _scheduledRewardAmount = 0;
        _rewardReleaseTime = 0;
        recipient.transfer(amount);
    }
    function getScheduledRewardInfo() public view returns (address, uint256, uint256, bool) {
        return (_scheduledRewardRecipient, _scheduledRewardAmount, _rewardReleaseTime, _rewardScheduled);
    }
    // === END FALLBACK INJECTION ===

}